
// === Includes ===
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
#include <syslog.h>
#include <search.h>
#include <sqlite3.h>
#include <pthread.h>

#define HASH_ALLOC

#define MAX_RECIPIENTS 		100
#define MAX_KNOWNSENDERS	(1 << 20)

// === Global definitions ===
static sqlite3 *db = NULL;

enum flags {
	FLAG_EMPTY			= 0x00,
	FLAG_CHECK_HTMLMAILONLY		= 0x01,
	FLAG_CHECK_NEWSENDERSONLY	= 0x02,
	FLAG_CHECK_BLONLY		= 0x04,
	FLAG_DRY			= 0x10,
};
typedef enum flags flags_t;
static flags_t flags = FLAG_EMPTY;

static int todomains_limit = 3;

struct private {
	char			*mailfrom;
	char 			 mailfrom_isnew;
	char			 sender_blacklisted;
	char			 body_hashtml;
	int 			 todomains;
	struct hsearch_data 	 todomain_htab;
#ifdef HASH_ALLOC
	char			*todomain[MAX_RECIPIENTS];
#endif
};
typedef struct private private_t;

static struct hsearch_data mailfrom_htab={0};
static pthread_mutex_t mailfrom_mutex;

#ifdef HASH_ALLOC
static int   mailfroms = 0;
static char *mailfrom[MAX_KNOWNSENDERS];
#endif

#define R(a) (flags&FLAG_DRY ? SMFIS_CONTINUE : a)

// === SQLite3 routines ===

void mailfrom_htab_add(const char const *mailfrom_in) {
#ifdef HASH_ALLOC
	char *mailfrom_cur = strdup(mailfrom_in);
	mailfrom[mailfroms++] = mailfrom_cur;
#else
	char *mailfrom_cur = *mailfrom_in;
#endif

	ENTRY entry, *ret;
	entry.key  = (char *)mailfrom_cur;
	entry.data = (void *)1;
	if(!hsearch_r(entry, ENTER, &ret, &mailfrom_htab)) {
		syslog(LOG_CRIT, "mailfrom_htab_add(): Cannot insert new \"MAIL FROM\" entry (too small MAX_KNOWNSENDERS?): %s (errno: %i). Exit.\n",
			strerror(errno), errno);
		exit(EX_SOFTWARE);
	}
	syslog(LOG_NOTICE, "mailfrom_htab_add(): \"%s\".\n", mailfrom_cur);

	return;
}

static int mailfrom_get_callback(void *nullarg, int argc, char **argv, char **colname) {
	int i;
	i=0;
	while(i<argc) {
		if(!strcmp(colname[i], "mailfrom"))
			mailfrom_htab_add(argv[i]);
		i++;
	}
	return 0;
}

void mailfrom_get() {
	char query[BUFSIZ];
	int rc;
	char *errmsg = NULL;

	if(!hcreate_r(MAX_KNOWNSENDERS, &mailfrom_htab)) {
		syslog(LOG_CRIT, "mailfrom_get(): Failure on hcreate_r(): %s (errno: %i). Exit.\n", strerror(errno), errno);
		exit(EX_SOFTWARE);
	}

	sprintf(query, "DELETE FROM tocheckmilter_mailfrom WHERE dom < strftime('%%s', 'now')-(3600*24*365)");
	rc = sqlite3_exec(db, query, (int (*)(void *, int,  char **, char **))mailfrom_get_callback, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot delete expired \"MAIL FROM\" from history in DB: %s. Exit.\n", errmsg);
		exit(EX_SOFTWARE);
	}

	sprintf(query, "SELECT mailfrom FROM tocheckmilter_mailfrom");
	rc = sqlite3_exec(db, query, (int (*)(void *, int,  char **, char **))mailfrom_get_callback, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot get valid \"MAIL FROM\" history from DB: %s. Exit.\n", errmsg);
		exit(EX_SOFTWARE);
	}
	return;
}

void mailfrom_upd(const char const *mailfrom) {
	char query[BUFSIZ];
	int rc;
	char *errmsg = NULL;
	sprintf(query, "UPDATE tocheckmilter_mailfrom SET count=count+1, dom=CURRENT_TIMESTAMP WHERE mailfrom=\"%s\"", 
		mailfrom);

	pthread_mutex_lock(&mailfrom_mutex);

	rc = sqlite3_exec(db, query, NULL, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot update \"MAIL FROM\" in history in DB: %s. Ignoring.\n", errmsg);
//		exit(EX_SOFTWARE);
	}

	pthread_mutex_unlock(&mailfrom_mutex);

	return;
}

void mailfrom_add(const char const *mailfrom) {
	char query[BUFSIZ];
	int rc;
	char *errmsg = NULL;
	sprintf(query, "INSERT INTO tocheckmilter_mailfrom VALUES(\"%s\", CURRENT_TIMESTAMP, 1)", 
		mailfrom);

	pthread_mutex_lock(&mailfrom_mutex);

	rc = sqlite3_exec(db, query, NULL, NULL, &errmsg);
	if(rc != SQLITE_OK) {
		syslog(LOG_CRIT, "Cannot insert new \"MAIL FROM\" into history in DB: %s. Ignoring.\n", errmsg);
//		exit(EX_SOFTWARE);
	}

	mailfrom_htab_add(mailfrom);

	pthread_mutex_unlock(&mailfrom_mutex);

	return;
}

int mailfrom_chk(const char const *mailfrom) {
	pthread_mutex_lock(&mailfrom_mutex);

	ENTRY entry, *ret;
	entry.key  = (char *)mailfrom;
	entry.data = (void *)1;
	hsearch_r(entry, FIND, &ret, &mailfrom_htab);

	pthread_mutex_unlock(&mailfrom_mutex);

	if(ret != NULL)
		return 1;

	syslog(LOG_NOTICE, "mailfrom_chk(): Cannot find \"%s\".\n", mailfrom);
	return 0;
}

void mailfrom_free() {
	hdestroy_r(&mailfrom_htab);

#ifdef HASH_ALLOC
	while(mailfroms--)
		free(mailfrom[mailfroms]);
#endif
	return;
}

// === Code ===

extern sfsistat tockmilter_cleanup(SMFICTX *, bool);

sfsistat tockmilter_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	private_t *private_p = calloc(1, sizeof(private_t));
	if(private_p == NULL) {
		syslog(LOG_NOTICE, "tockmilter_connect(): Cannot allocate memory. Exit.\n");
		exit(EX_SOFTWARE);
	}

	if(!hcreate_r(MAX_RECIPIENTS+2, &private_p->todomain_htab)) {
		syslog(LOG_NOTICE, "tockmilter_connect(): Failure on hcreate_r(). Exit.\n");
		exit(EX_SOFTWARE);
	}

	smfi_setpriv(ctx, private_p);

	return SMFIS_CONTINUE;
}

sfsistat tockmilter_helo(SMFICTX *ctx, char *helohost) {
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_envfrom(SMFICTX *ctx, char **argv) {

	if(argv[0] == NULL) {
		syslog(LOG_NOTICE, "%s: tockmilter_envfrom(): argv[0]==NULL. Sending TEMPFAIL.\n", smfi_getsymval(ctx, "i"));
		return R(SMFIS_TEMPFAIL);
	}
	if(*argv[0] == 0) {
		syslog(LOG_NOTICE, "%s: tockmilter_envfrom(): *argv[0]==0. Sending TEMPFAIL.\n", smfi_getsymval(ctx, "i"));
		return R(SMFIS_TEMPFAIL);
	}

	private_t *private_p = smfi_getpriv(ctx);

	private_p->mailfrom  = strdup(argv[0]);
	private_p->mailfrom_isnew = !mailfrom_chk(argv[0]);

	return SMFIS_CONTINUE;
}

sfsistat tockmilter_envrcpt(SMFICTX *ctx, char **argv) {
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_header(SMFICTX *ctx, char *headerf, char *_headerv) {
//	syslog(LOG_NOTICE, "%s: tockmilter_header(): \"%s\": \"%s\".\n", smfi_getsymval(ctx, "i"), headerf, _headerv);

	if(!strcasecmp(headerf, "To")) {

		private_t *private_p = smfi_getpriv(ctx);
		if(private_p == NULL) {
			syslog(LOG_NOTICE, "%s: tockmilter_header(): private_p == NULL. Skipping.\n", smfi_getsymval(ctx, "i"));
			return SMFIS_CONTINUE;
		}

		if(flags & FLAG_CHECK_NEWSENDERSONLY) 
			if(!private_p->mailfrom_isnew)
				return SMFIS_CONTINUE;

		char *at_saveptr = NULL;
		char *headerv = strdup(_headerv);
		strtok_r(headerv, "@", &at_saveptr);
		do {

			char *at = strtok_r(NULL, "@", &at_saveptr);

			if(at == NULL)
				break;

			char *domainend_saveptr = NULL;
			strtok_r(&at[1], " \n\t)(<>@,;:\"/[]?=", &domainend_saveptr);
			char *domainend = strtok_r(NULL, " \n\t)(<>@,;:\"/[]?=", &domainend_saveptr);

			if(domainend == NULL)
				break;

#ifdef HASH_ALLOC
			char *domain = malloc(domainend - at + 9);
#else
			char *domain = alloca(domainend - at + 9);
#endif
			memcpy(domain, at, domainend-at);
			domain[domainend-at] = 0;

			syslog(LOG_NOTICE, "%s: tockmilter_header(): todomain: %s.\n", smfi_getsymval(ctx, "i"), domain);

			ENTRY entry, *ret;

			entry.key  = domain;
			entry.data = (void *)1;

			hsearch_r(entry, FIND, &ret, &private_p->todomain_htab);

			if(ret == NULL) {
				hsearch_r(entry, ENTER, &ret, &private_p->todomain_htab);
#ifndef HASH_ALLOC
				private_p->todomains++;
			}
#else
				private_p->todomain[private_p->todomains++] = domain;
			} else
				free(domain);
#endif
		} while(private_p->todomains < MAX_RECIPIENTS);
		free(headerv);
	} else
	if(!strcasecmp(headerf, "X-DNSBL-MILTER")) {
		private_t *private_p = smfi_getpriv(ctx);
		if(!strcasecmp(_headerv, "Blacklisted")) {
			private_p->sender_blacklisted = 1;
		}
		syslog(LOG_NOTICE, "%s: tockmilter_header(): Found DNSBL header value: %s. Blacklisted: %u.\n",
			smfi_getsymval(ctx, "i"), _headerv, private_p->sender_blacklisted);
	}
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_eoh(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) {
	if(!(flags & FLAG_CHECK_HTMLMAILONLY))
		return SMFIS_CONTINUE;

//	syslog(LOG_NOTICE, "%s: tockmilter_body(): \"%s\".\n", smfi_getsymval(ctx, "i"), bodyp);

	private_t *private_p = smfi_getpriv(ctx);
	if(strstr((char *)bodyp, "\nContent-Type: text/html")) {
		private_p->body_hashtml = 1;
		syslog(LOG_NOTICE, "%s: tockmilter_body(): Seems, that here's HTML included.\n", smfi_getsymval(ctx, "i"));
	}
	return SMFIS_CONTINUE;
}

static inline int tockmilter_eom_ok(SMFICTX *ctx, private_t *private_p) {
	smfi_addheader(ctx, "X-ToChk-Milter", "passed");
	if(private_p->mailfrom_isnew)
		mailfrom_add(private_p->mailfrom);
	else
		mailfrom_upd(private_p->mailfrom);
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_eom(SMFICTX *ctx) {
	private_t *private_p = smfi_getpriv(ctx);
	if(private_p == NULL) {
		syslog(LOG_NOTICE, "%s: tockmilter_eom(): private_p == NULL. Skipping.\n", smfi_getsymval(ctx, "i"));
		return SMFIS_CONTINUE;
	}

	syslog(LOG_NOTICE, "%s: tockmilter_eom(): Total: mailfrom_isnew == %u; to_domains == %u, body_hashtml == %u, sender_blacklisted == %u.\n", 
		smfi_getsymval(ctx, "i"), private_p->mailfrom_isnew, private_p->todomains, private_p->body_hashtml, private_p->sender_blacklisted);

	if(flags & FLAG_CHECK_NEWSENDERSONLY) 
		if(!private_p->mailfrom_isnew) 
			return tockmilter_eom_ok(ctx, private_p);

	if(flags & FLAG_CHECK_HTMLMAILONLY)
		if(!private_p->body_hashtml)
			return tockmilter_eom_ok(ctx, private_p);

	if(flags & FLAG_CHECK_BLONLY)
		if(!private_p->sender_blacklisted)
			return tockmilter_eom_ok(ctx, private_p);

	if(private_p->todomains > todomains_limit) {
		syslog(LOG_NOTICE, "%s: tockmilter_eom(): Too many domains in \"To\" field: %u > %u. Sending SMFIS_REJECT.\n", 
			smfi_getsymval(ctx, "i"), private_p->todomains, todomains_limit);
		return R(SMFIS_REJECT);
	}

	return tockmilter_eom_ok(ctx, private_p);
}

sfsistat tockmilter_abort(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_close(SMFICTX *ctx) {
	private_t *private_p = smfi_getpriv(ctx);
	if(private_p == NULL) {
		syslog(LOG_NOTICE, "%s: tockmilter_close(): private_p == NULL. Skipping.\n", smfi_getsymval(ctx, "i"));
		return SMFIS_CONTINUE;
	}

	hdestroy_r(&private_p->todomain_htab);
#ifdef HASH_ALLOC
	while(private_p->todomains--) {
		free(private_p->todomain[private_p->todomains]);
	}
#endif
	free(private_p->mailfrom);
	free(private_p);
	smfi_setpriv(ctx, NULL);

	return SMFIS_CONTINUE;
}

sfsistat tockmilter_unknown(SMFICTX *ctx, const char *cmd) {
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_data(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat tockmilter_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
	SMFICTX *ctx;
	unsigned long f0;
	unsigned long f1;
	unsigned long f2;
	unsigned long f3;
	unsigned long *pf0;
	unsigned long *pf1;
	unsigned long *pf2;
	unsigned long *pf3;
{
	return SMFIS_ALL_OPTS;
}

static void usage(const char *path) {
	fprintf(stderr, "Usage: %s -p socket-addr [-t timeout] [-L domain limit] [-N /path/to/sqlite/db] [-HdB]\n",
		path);
}

int main(int argc, char *argv[]) {
	struct smfiDesc mailfilterdesc = {
		"ToCheckMilter",		// filter name
		SMFI_VERSION,			// version code -- do not change
		SMFIF_ADDHDRS|SMFIF_ADDRCPT,	// flags
		tockmilter_connect,		// connection info filter
		tockmilter_helo,		// SMTP HELO command filter
		tockmilter_envfrom,		// envelope sender filter
		tockmilter_envrcpt,		// envelope recipient filter
		tockmilter_header,		// header filter
		tockmilter_eoh,			// end of header
		tockmilter_body,		// body block filter
		tockmilter_eom,			// end of message
		tockmilter_abort,		// message aborted
		tockmilter_close,		// connection cleanup
		tockmilter_unknown,		// unknown SMTP commands
		tockmilter_data,		// DATA command
		tockmilter_negotiate		// Once, at the start of each SMTP connection
	};

	char setconn = 0;
	int c;
	const char *args = "p:t:hHdN:L:B";
	extern char *optarg;
	// Process command line options
	while ((c = getopt(argc, argv, args)) != -1) {
		switch (c) {
			case 'p':
				if (optarg == NULL || *optarg == '\0')
				{
					(void)fprintf(stderr, "Illegal conn: %s\n",
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_setconn(optarg) == MI_FAILURE)
				{
					(void)fprintf(stderr,
						"smfi_setconn failed\n");
					exit(EX_SOFTWARE);
				}

				if (strncasecmp(optarg, "unix:", 5) == 0)
					unlink(optarg + 5);
				else if (strncasecmp(optarg, "local:", 6) == 0)
					unlink(optarg + 6);
				setconn = 1;
				break;
			case 't':
				if (optarg == NULL || *optarg == '\0') {
					(void)fprintf(stderr, "Illegal timeout: %s\n", 
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_settimeout(atoi(optarg)) == MI_FAILURE) {
					(void)fprintf(stderr,
						"smfi_settimeout failed\n");
					exit(EX_SOFTWARE);
				}
				break;
			case 'd':
				flags |= FLAG_DRY;
				break;
			case 'H':
				flags |= FLAG_CHECK_HTMLMAILONLY;
				break;
			case 'B':
				flags |= FLAG_CHECK_BLONLY;
				break;
			case 'N':
                                // Openning the DB
				if(sqlite3_open_v2(optarg, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
//                              if(sqlite3_open(optarg, &db)) {
					fprintf(stderr, "Cannot open SQLite3 DB-file \"%s\"\n", optarg);
					exit(EX_SOFTWARE);
				}

				// Checking it's validness. Fixing if required.
				int rc;
				sqlite3_stmt *stmt = NULL;
				rc = sqlite3_prepare_v2(db, "SELECT mailfrom, dom, count FROM tocheckmilter_mailfrom LIMIT 1", -1, &stmt, NULL);
				if(rc != SQLITE_OK) {
					// Fixing the table "statmilter_stats"
					fprintf(stderr, "Invalid DB file \"%s\". Recreating table \"tocheckmilter_mailfrom\" in it.\n", optarg);
					sqlite3_exec(db, "DROP TABLE tocheckmilter_mailfrom", NULL, NULL, NULL);
					sqlite3_exec(db, "CREATE TABLE tocheckmilter_mailfrom (mailfrom VARCHAR(255), dom timestamp DEFAULT CURRENT_TIMESTAMP, count integer(8) DEFAULT 0)", NULL, NULL, NULL);
					sqlite3_exec(db, "CREATE UNIQUE INDEX mailfrom_idx ON tocheckmilter_mailfrom (mailfrom)", NULL, NULL, NULL);
					sqlite3_exec(db, "CREATE INDEX dom_idx ON tocheckmilter_mailfrom (dom)", NULL, NULL, NULL);
				}
				sqlite3_finalize(stmt);
				break;
			case 'l':
				todomains_limit = atoi(optarg);
				break;
			case 'h':
			default:
				usage(argv[0]);
				exit(EX_USAGE);
		}
	}
	if(!setconn) {
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}
	if(smfi_register(mailfilterdesc) == MI_FAILURE) {
		fprintf(stderr, "smfi_register() failed\n");
		exit(EX_UNAVAILABLE);
	}
	if(pthread_mutex_init(&mailfrom_mutex, NULL)) {
		fprintf(stderr, "pthread_mutex_init() failed\n");
		exit(EX_SOFTWARE);
	}
	openlog(NULL, LOG_PID, LOG_MAIL);
	mailfrom_get();
	int ret = smfi_main();
	sqlite3_close(db);
	closelog();
	mailfrom_free();
	pthread_mutex_destroy(&mailfrom_mutex);
	return ret;
}

