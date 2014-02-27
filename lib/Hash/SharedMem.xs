#define PERL_NO_GET_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <sys/mman.h>

/* Perl compatibility */

#define PERL_VERSION_DECIMAL(r,v,s) (r*1000000 + v*1000 + s)
#define PERL_DECIMAL_VERSION \
	PERL_VERSION_DECIMAL(PERL_REVISION,PERL_VERSION,PERL_SUBVERSION)
#define PERL_VERSION_GE(r,v,s) \
	(PERL_DECIMAL_VERSION >= PERL_VERSION_DECIMAL(r,v,s))

#ifndef CvPROTO
# define CvPROTO(cv) SvPVX((SV*)(cv))
# define CvPROTOLEN(cv) SvCUR((SV*)(cv))
#endif /* !CvPROTO */

/* Perl additions */

#define likely(t) LIKELY(!!(t))
#define unlikely(t) UNLIKELY(!!(t))

typedef U64TYPE U64;

#define sv_is_glob(sv) (SvTYPE(sv) == SVt_PVGV)

#if PERL_VERSION_GE(5,11,0)
# define sv_is_regexp(sv) (SvTYPE(sv) == SVt_REGEXP)
#else /* <5.11.0 */
# define sv_is_regexp(sv) 0
#endif /* <5.11.0 */

#define sv_is_undef(sv) (!sv_is_glob(sv) && !sv_is_regexp(sv) && !SvOK(sv))

#define sv_is_string(sv) \
	(!sv_is_glob(sv) && !sv_is_regexp(sv) && \
	 (SvFLAGS(sv) & (SVf_IOK|SVf_NOK|SVf_POK|SVp_IOK|SVp_NOK|SVp_POK)))

#define bool_sv(b) ((b) ? &PL_sv_yes : &PL_sv_no)

/* fd closing on scope stack */

static void THX_closefd_cleanup(pTHX_ void *fd_p_v)
{
	int fd = *(int*)fd_p_v;
	Safefree(fd_p_v);
	if(unlikely(fd != -1)) close(fd);
}

#define closefd_save(fd) THX_closefd_save(aTHX_ fd)
static int *THX_closefd_save(pTHX_ int fd)
{
	int *fd_p;
	Newx(fd_p, 1, int);
	*fd_p = fd;
	SAVEDESTRUCTOR_X(THX_closefd_cleanup, fd_p);
	return fd_p;
}

#define closefd_cancel(fdp) THX_closefd_cancel(aTHX_ fdp)
static void THX_closefd_cancel(pTHX_ int *fd_p)
{
	*fd_p = -1;
}

#define closefd_early(fdp) THX_closefd_early(aTHX_ fdp)
static void THX_closefd_early(pTHX_ int *fd_p)
{
	int fd = *fd_p;
	if(likely(fd != -1)) {
		*fd_p = -1;
		(void) close(fd);
	}
}

typedef int *closefd_ref_t;

/* directory stream closing on scope stack */

static void THX_closedirh_cleanup(pTHX_ void *dirh_p_v)
{
	DIR *dirh = *(DIR**)dirh_p_v;
	Safefree(dirh_p_v);
	if(unlikely(dirh)) closedir(dirh);
}

#define closedirh_save(dirh) THX_closedirh_save(aTHX_ dirh)
static DIR **THX_closedirh_save(pTHX_ DIR *dirh)
{
	DIR **dirh_p;
	Newx(dirh_p, 1, DIR*);
	*dirh_p = dirh;
	SAVEDESTRUCTOR_X(THX_closedirh_cleanup, dirh_p);
	return dirh_p;
}

#define closedirh_early(dirhp) THX_closedirh_early(aTHX_ dirhp)
static void THX_closedirh_early(pTHX_ DIR **dirh_p)
{
	DIR *dirh = *dirh_p;
	if(likely(dirh)) {
		*dirh_p = NULL;
		(void) closedir(dirh);
	}
}

typedef DIR **closedirh_ref_t;

/* file removal on scope stack */

struct unlinkfile_cleanup_par {
	int dir_fd;
	char filename[1]; /* struct hack */
};

static void THX_unlinkfile_cleanup(pTHX_ void *par_p_v)
{
	struct unlinkfile_cleanup_par *par_p = par_p_v;
	int dir_fd = par_p->dir_fd;
	if(unlikely(dir_fd != -1))
		(void) unlinkat(dir_fd, par_p->filename, 0);
	Safefree(par_p_v);
}

#define unlinkfile_save(dir_fd, fn) THX_unlinkfile_save(aTHX_ dir_fd, fn)
static struct unlinkfile_cleanup_par *THX_unlinkfile_save(pTHX_ int dir_fd,
	char const *filename)
{
	struct unlinkfile_cleanup_par *par_p;
	char *par_p_c;
	size_t fnlen = strlen(filename) + 1;
	Newx(par_p_c, offsetof(struct unlinkfile_cleanup_par, filename) + fnlen,
		char);
	par_p = (struct unlinkfile_cleanup_par *)par_p_c;
	par_p->dir_fd = dir_fd;
	(void) memcpy(par_p->filename, filename, fnlen);
	SAVEDESTRUCTOR_X(THX_unlinkfile_cleanup, par_p);
	return par_p;
}

#define unlinkfile_cancel(par_p) THX_unlinkfile_cancel(aTHX_ par_p)
static void THX_unlinkfile_cancel(pTHX_ struct unlinkfile_cleanup_par *par_p)
{
	par_p->dir_fd = -1;
}

#define unlinkfile_early(par_p) THX_unlinkfile_early(aTHX_ par_p)
static void THX_unlinkfile_early(pTHX_ struct unlinkfile_cleanup_par *par_p)
{
	int dir_fd = par_p->dir_fd;
	if(likely(dir_fd != -1)) {
		par_p->dir_fd = -1;
		(void) unlinkat(dir_fd, par_p->filename, 0);
	}
}

typedef struct unlinkfile_cleanup_par *unlinkfile_ref_t;

/*
 * mutable parameters
 *
 * LINE_SZ_LOG2 and PAGE_SZ_LOG2 are meant to match the target
 * architecture.  MAXSPLAY must be tuned empirically.  Line size 2^6
 * and page size 2^12 here match the ia32/amd64 processors that are
 * common in 2013, and MAXSPLAY 15 is the result of an experiment with
 * an amd64 system.  (Perhaps it is a sweet spot due to node buffers
 * coming in just under a power of two size.)
 *
 * FUTURE: should detect line size and page size automatically.
 *
 * FUTURE: should experiment with MAXSPLAY on more systems, to come up
 * with a formula that optimises it more widely.
 */

#define LINE_SZ_LOG2 6
#define PAGE_SZ_LOG2 12
#define MAXSPLAY 15

/* byte definition */

typedef U8 byte;
#define BYTE_MAX 0xff

/* word definition */

#define WORD_SZ_LOG2 3
typedef U64 word;
#define WORD_C UINT64_C
#define WORD_MAX WORD_C(0xffffffffffffffff)

/* alignment handling */

#define WORD_SZ (1<<WORD_SZ_LOG2)
#define LINE_SZ (1<<LINE_SZ_LOG2)
#define PAGE_SZ (1<<PAGE_SZ_LOG2)
#define IS_POW2_ALIGNED(v, a) (!((v) & ((a)-1)))
#define IS_WORD_ALIGNED(v) IS_POW2_ALIGNED(v, WORD_SZ)
#define IS_LINE_ALIGNED(v) IS_POW2_ALIGNED(v, LINE_SZ)
#define IS_PAGE_ALIGNED(v) IS_POW2_ALIGNED(v, PAGE_SZ)
#define POW2_ALIGN(v, a) ((((v)-1) | ((a)-1)) + 1)
#define WORD_ALIGN(v) POW2_ALIGN(v, WORD_SZ)
#define LINE_ALIGN(v) POW2_ALIGN(v, LINE_SZ)
#define PAGE_ALIGN(v) POW2_ALIGN(v, PAGE_SZ)

/* check parameter validity */

#if LINE_SZ_LOG2 < WORD_SZ_LOG2
 #error bad parameter: line smaller than word
#endif /* LINE_SZ_LOG2 < WORD_SZ_LOG2 */
#if PAGE_SZ_LOG2 < LINE_SZ_LOG2
 #error bad parameter: page smaller than line
#endif /* PAGE_SZ_LOG2 < LINE_SZ_LOG2 */
#if MAXSPLAY < 3 || MAXSPLAY >= BYTE_MAX || !(MAXSPLAY & 1)
 #error bad parameter: splay limit unacceptable
#endif /* MAXSPLAY < 3 || MAXSPLAY >= BYTE_MAX || !(MAXSPLAY & 1) */

/* lower size limit for ordinary btree nodes */

#define MINSPLAY ((MAXSPLAY+1)>>1)

/*
 * magic numbers
 *
 * The parameter word value that this defines is the only set of
 * parameters that the code supports.  It's not actually a magic number,
 * but by requiring an exact match it comes rather close to one in
 * practice.
 *
 * FUTURE: could handle shashes that have non-preferred parameters by
 * treating the parameters as variables.
 *
 * FUTURE: if there is any change in the file formats, it should be
 * indicated by setting flags or changing a version number in the
 * parameter word.  ext2's concept of readonly-compatible changes may
 * be useful.
 */

#define DATA_FILE_MAGIC WORD_C(0xc693dac5ed5e47c2)
#define MASTER_FILE_MAGIC WORD_C(0xa58afd185cbf5af7)
#define PARAMETER_WORD (LINE_SZ_LOG2 | (PAGE_SZ_LOG2<<8) | (MAXSPLAY<<16))

/*
 * data file header layout
 *
 * The zero padding after the initial immutable words (filling the
 * remainder of the first line, unless lines are very small) is picked
 * out as a feature of the header so that it can be used to represent
 * the empty btree node and the empty string.
 */

#define DHD_MAGIC 0
#define DHD_PARAM (DHD_MAGIC+WORD_SZ)
#define DHD_LENGTH (DHD_PARAM+WORD_SZ)
#define DHD_ZEROPAD (DHD_LENGTH+WORD_SZ)
#define DHD_ZEROPAD_END LINE_ALIGN(DHD_ZEROPAD)
#define DHD_NEXTALLOC_SPACE DHD_ZEROPAD_END
#define DHD_CURRENT_ROOT LINE_ALIGN(DHD_NEXTALLOC_SPACE+WORD_SZ)
#define DHD_SZ LINE_ALIGN(DHD_CURRENT_ROOT+WORD_SZ)

#define DHD_ZEROPAD_SZ (DHD_ZEROPAD_END-DHD_ZEROPAD)

/* master file layout */

#define MFL_MAGIC 0
#define MFL_PARAM (MFL_MAGIC+WORD_SZ)
#define MFL_LASTALLOC_DATAFILEID LINE_ALIGN(MFL_PARAM+WORD_SZ)
#define MFL_CURRENT_DATAFILEID LINE_ALIGN(MFL_LASTALLOC_DATAFILEID+WORD_SZ)
#define MFL_SZ PAGE_ALIGN(MFL_CURRENT_DATAFILEID+WORD_SZ)

/*
 * memory dereferencing
 *
 * BYTE_AT() and WORD_AT() are syntactic sugar for working with offsets
 * into memory maps.
 *
 * sync_read_word() is intended to provide atomic reading of a
 * mutable word, ordered relative to other memory operations.  It is
 * a counterpart to the built-in __sync_bool_compare_and_swap(), which
 * performs an atomic compare-and-set.  However, the C language (even
 * with gcc extensions) doesn't actually provide a way to guarantee that
 * a read is atomic.  This implementation, using a "volatile" qualifier,
 * ensures that the operation is a memory barrier, but doesn't guarantee
 * atomicity.  We must hope that the compiler uses a native atomic
 * read instruction.
 */

#define BYTE_AT(base, offset) (*(byte*)(((char*)(base))+(offset)))
#define WORD_AT(base, offset) (*(word*)(((char*)(base))+(offset)))

static word sync_read_word(word const *ptr)
{
	return *(word const volatile *)ptr;
}

/* refcounted handling of mmaps */

#define mmap_addr_from_sv(mapsv) THX_mmap_addr_from_sv(aTHX_ mapsv)
static void *THX_mmap_addr_from_sv(pTHX_ SV *mapsv)
{
	return (void *)SvPVX(mapsv);
}

#define mmap_len_from_sv(mapsv) THX_mmap_len_from_sv(aTHX_ mapsv)
static size_t THX_mmap_len_from_sv(pTHX_ SV *mapsv)
{
	return (size_t)SvUVX(mapsv);
}

static int THX_mmap_mg_free(pTHX_ SV *sv, MAGIC *mg)
{
	void *addr;
	PERL_UNUSED_ARG(mg);
	addr = mmap_addr_from_sv(sv);
	if(likely(addr)) (void) munmap(addr, mmap_len_from_sv(sv));
	return 0;
}

static MGVTBL const mmap_mgvtbl = {
	NULL, /* get */
	NULL, /* set */
	NULL, /* len */
	NULL, /* clear */
	THX_mmap_mg_free, /* free */
	NULL, /* copy */
	NULL, /* dup */
	NULL, /* local */
};

#define mmap_early_unmap(mapsv) THX_mmap_early_unmap(aTHX_ mapsv)
static void THX_mmap_early_unmap(pTHX_ SV *mapsv)
{
	(void) sv_unmagicext(mapsv, PERL_MAGIC_ext, (MGVTBL*)&mmap_mgvtbl);
}

#define mmap_as_sv(fd, len, wr) THX_mmap_as_sv(aTHX_ fd, len, wr)
static SV *THX_mmap_as_sv(pTHX_ int fd, word len, bool writable)
{
	SV *mapsv;
	void *addr;
	if(unlikely((word)(size_t)len != len || (word)(UV)len != len)) {
		errno = ENOMEM;
		return NULL;
	}
	mapsv = sv_2mortal(newSV_type(SVt_PVMG));
	(void) sv_magicext(mapsv, NULL, PERL_MAGIC_ext, &mmap_mgvtbl, NULL, 0);
	addr = mmap(NULL, len, writable ? (PROT_READ|PROT_WRITE) : PROT_READ,
		MAP_SHARED, fd, 0);
	if(unlikely(addr == MAP_FAILED)) return NULL;
	SvPV_set(mapsv, (char *)addr);
	SvUV_set(mapsv, len);
	return mapsv;
}

/*
 * top-level shash representation
 *
 * The same structure is used both for live shash handles that can
 * update and for snapshot handles.  Where a live shash has a memory
 * mapping of the master file, a snapshot has a frozen root pointer.
 * Both types of handle have a memory mapping of the data file.  A live
 * shash also has a file descriptor pointing at the directory.
 *
 * The same mode flag set is used for opening modes and for handle modes,
 * because of the overlap.
 *
 * FUTURE: should also support a handle type representing an uncommitted
 * transaction.  This snapshots root pointer at first read operation,
 * and then records read and write operations performed on it and their
 * results.  It can check whether any conflicting write has occurred
 * by retrying the read operations from new shared root and comparing
 * results; as an optimisation, if the shared root hasn't changed from
 * the snapshot then no write has occurred.  This check can be exposed
 * as a method to allow the caller to abort a doomed transaction early.
 * When it tries to commit, if no conflicting write has occurred,
 * it performs the recorded write operations, then tries to replace
 * the root.  If the root has changed, it must go back to the check for
 * conflicting writes, and potentially perform its own writes again.
 * (A standard writable handle acts as a transaction handle that
 * automatically commits on every operation.)
 *
 * FUTURE: should have a mode flag to synch file data where necessary
 * to keep disk image consistent.  Would ensure that data file writes
 * complete before root-pointer replacement occurs, but doesn't need to
 * wait for disk writes to actually complete.
 *
 *
 * FUTURE: should have a mode flag or method (or both) to wait for
 * root-pointer replacement to complete synchronously, to achieve
 * durability of writes.  Only meaningful if using the mode that keeps
 * the disk image consistent, so as a mode it implies the consistency
 * mode, and as a method it's invalid without the consistency mode.
 */

#define STOREMODE_READ     0x01
#define STOREMODE_WRITE    0x02
#define STOREMODE_CREATE   0x04
#define STOREMODE_EXCLUDE  0x08
#define STOREMODE_SNAPSHOT 0x10

struct shash {
	SV *top_pathname_sv;
	unsigned mode;
	SV *data_mmap_sv;
	void *data_mmap;
	word data_size;
	union {
		struct {
			int dir_fd;
			SV *master_mmap_sv;
			void *master_mmap;
			word data_file_id;
			byte *prealloc_loc;
			word prealloc_len;
		} live;
		struct {
			word root;
		} snapshot;
	} u;
};

static HV *shash_handle_stash;

#define arg_is_shash(arg) THX_arg_is_shash(aTHX_ arg)
static bool THX_arg_is_shash(pTHX_ SV *arg)
{
	SV *shsv;
	return SvROK(arg) && (shsv = SvRV(arg)) && SvOBJECT(shsv) &&
			SvSTASH(shsv) == shash_handle_stash;
}

#define arg_error_notshash() THX_arg_error_notshash(aTHX)
static void THX_arg_error_notshash(pTHX) __attribute__noreturn__;
static void THX_arg_error_notshash(pTHX)
{
	croak("handle is not a shared hash handle");
}

#define arg_check_shash(arg) THX_arg_check_shash(aTHX_ arg)
static void THX_arg_check_shash(pTHX_ SV *arg)
{
	if(!likely(arg_is_shash(arg))) arg_error_notshash();
}

#define shash_from_svref(shsvref) THX_shash_from_svref(aTHX_ shsvref)
static struct shash *THX_shash_from_svref(pTHX_ SV *shsvref)
{
	SV *shsv;
	if(!likely(SvROK(shsvref) && (shsv = SvRV(shsvref)) && SvOBJECT(shsv) &&
			SvSTASH(shsv) == shash_handle_stash))
		arg_error_notshash();
	return (struct shash *)SvPVX(shsv);
}

#define shash_error(sh, act, msg) THX_shash_error(aTHX_ sh, act, msg)
static void THX_shash_error(pTHX_ struct shash *sh, char const *action,
	char const *message) __attribute__noreturn__;
static void THX_shash_error(pTHX_ struct shash *sh, char const *action,
	char const *message)
{
	croak("can't %s shared hash %s: %s", action,
		SvPV_nolen(sh->top_pathname_sv), message);
}

#define shash_error_data(sh) THX_shash_error_data(aTHX_ sh)
static void THX_shash_error_data(pTHX_ struct shash *sh)
	__attribute__noreturn__;
static void THX_shash_error_data(pTHX_ struct shash *sh)
{
	shash_error(sh, "use", "shared hash is corrupted");
}

#define shash_error_errnum(sh, act, en) \
	THX_shash_error_errnum(aTHX_ sh, act, en)
static void THX_shash_error_errnum(pTHX_ struct shash *sh, char const *action,
	int errnum) __attribute__noreturn__;
static void THX_shash_error_errnum(pTHX_ struct shash *sh, char const *action,
	int errnum)
{
	shash_error(sh, action, Strerror(errnum));
}

#define shash_error_errno(sh, act) THX_shash_error_errno(aTHX_ sh, act)
static void THX_shash_error_errno(pTHX_ struct shash *sh, char const *action)
	__attribute__noreturn__;
static void THX_shash_error_errno(pTHX_ struct shash *sh, char const *action)
{
	shash_error_errnum(sh, action, errno);
}

#define shash_check_readable(sh) THX_shash_check_readable(aTHX_ sh)
static void THX_shash_check_readable(pTHX_ struct shash *sh)
{
	if(!likely(sh->mode & STOREMODE_READ))
		shash_error(sh, "read",
			"shared hash was opened in unreadable mode");
}

#define shash_check_writable(sh) THX_shash_check_writable(aTHX_ sh)
static void THX_shash_check_writable(pTHX_ struct shash *sh)
{
	if(unlikely(sh->mode & STOREMODE_SNAPSHOT))
		shash_error(sh, "write", "shared hash handle is a snapshot");
	if(!likely(sh->mode & STOREMODE_WRITE))
		shash_error(sh, "write",
			"shared hash was opened in unwritable mode");
}

/* shash file handling */

#define FILENAME_PREFIX_LEN 10
#define MASTER_FILENAME "iNmv0,m$%3"
#define DATA_FILENAME_PREFIX "&\"JBLMEgGm"
#define DATA_FILENAME_SUFFIX_LEN (WORD_SZ<<1)
#define TEMP_FILENAME_PREFIX "DNaM6okQi;"

#define DATA_FILENAME_BUFSIZE (FILENAME_PREFIX_LEN+DATA_FILENAME_SUFFIX_LEN+1)

#define dir_make_data_filename(buf, fid) \
	THX_dir_make_data_filename(aTHX_ buf, fid)
static void THX_dir_make_data_filename(pTHX_ char *buf, word fileid)
{
	(void) sprintf(buf, "%s%08lx%08lx",
		DATA_FILENAME_PREFIX, (unsigned long)(fileid >> 32),
		(unsigned long)(fileid & WORD_C(0xffffffff)));
}

#define TEMP_FILENAME_BUFSIZE (FILENAME_PREFIX_LEN+8+8+8+1)

#define dir_make_temp_file(sh, fb) THX_dir_make_temp_file(aTHX_ sh, fb)
static int THX_dir_make_temp_file(pTHX_ struct shash *sh, char *fnbuf)
{
	struct timespec tsr;
	(void) clock_gettime(CLOCK_REALTIME, &tsr);
	(void) sprintf(fnbuf, "%s%08lx%08lx%08lx",
		TEMP_FILENAME_PREFIX, (unsigned long)tsr.tv_sec,
		(unsigned long)tsr.tv_nsec, (unsigned long)getpid());
	return openat(sh->u.live.dir_fd, fnbuf,
		O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0666);
}

enum {
	FILENAME_CLASS_BOGUS,
	FILENAME_CLASS_MASTER,
	FILENAME_CLASS_TEMP,
	FILENAME_CLASS_DATA
};

#define dir_filename_class(fn, id_p) THX_dir_filename_class(aTHX_ fn, id_p)
static int THX_dir_filename_class(pTHX_ char const *filename, word *id_p)
{
	size_t fnlen;
	if(filename[0] == '.') return FILENAME_CLASS_MASTER;
	fnlen = strlen(filename);
	if(fnlen == FILENAME_PREFIX_LEN &&
			memcmp(filename, MASTER_FILENAME,
				FILENAME_PREFIX_LEN) == 0)
		return FILENAME_CLASS_MASTER;
	if(fnlen >= FILENAME_PREFIX_LEN &&
			memcmp(filename, TEMP_FILENAME_PREFIX,
					FILENAME_PREFIX_LEN) == 0)
		return FILENAME_CLASS_TEMP;
	if(likely(fnlen == FILENAME_PREFIX_LEN+DATA_FILENAME_SUFFIX_LEN &&
			memcmp(filename, DATA_FILENAME_PREFIX,
				FILENAME_PREFIX_LEN) == 0)) {
		char const *p;
		word id = 0;
		for(p = filename+FILENAME_PREFIX_LEN; ; p++) {
			char c = *p;
			word v;
			if(!c) break;
			if(likely(c >= '0' && c <= '9')) {
				v = c - '0';
			} else if(likely(c >= 'a' && c <= 'f')) {
				v = c - 'a' + 10;
			} else {
				return FILENAME_CLASS_BOGUS;
			}
			id = (id << 4) | v;
		}
		if(likely(id != 0)) {
			*id_p = id;
			return FILENAME_CLASS_DATA;
		}
	}
	return FILENAME_CLASS_BOGUS;
}

#define dir_iterate(sh, act, iter, arg) \
	THX_dir_iterate(aTHX_ sh, act, iter, arg)
static void THX_dir_iterate(pTHX_ struct shash *sh, char const *action,
	void (*THX_iterate)(pTHX_ struct shash *sh, char const *fn, word arg),
	word arg)
{
	int dirhfd = fcntl(sh->u.live.dir_fd, F_DUPFD_CLOEXEC, 3);
	closefd_ref_t dirhfdr = closefd_save(dirhfd);
	DIR *dirh = fdopendir(dirhfd);
	closedirh_ref_t dirhr;
	if(!likely(dirh)) {
		if(!unlikely(action)) {
			closefd_early(dirhfdr);
			return;
		}
		shash_error_errno(sh, action);
	}
	closefd_cancel(dirhfdr);
	dirhr = closedirh_save(dirh);
	rewinddir(dirh);
	while(1) {
		struct dirent de, *der;
		int err = readdir_r(dirh, &de, &der);
		if(unlikely(err)) {
			if(!unlikely(action)) break;
			shash_error_errnum(sh, action, err);
		}
		if(!likely(der)) break;
		THX_iterate(aTHX_ sh, de.d_name, arg);
	}
	closedirh_early(dirhr);
}

static void THX_dir_clean_file(pTHX_ struct shash *sh, char const *fn,
	word curfileid)
{
	word fileid;
	int cls = dir_filename_class(fn, &fileid);
	if(unlikely(cls == FILENAME_CLASS_TEMP ||
			(cls == FILENAME_CLASS_DATA &&
			 unlikely((curfileid - fileid - 1) <
					(((word)1) << 62)))))
		(void) unlinkat(sh->u.live.dir_fd, fn, 0);
}

#define dir_clean(sh, curfileid) THX_dir_clean(aTHX_ sh, curfileid)
static void THX_dir_clean(pTHX_ struct shash *sh, word curfileid)
{
	dir_iterate(sh, NULL, THX_dir_clean_file, curfileid);
}

/*
 * shash operation fundamentals
 *
 * Allocation of space in the shash is slightly complexified in order to
 * use space efficiently, because at the low level allocation must be of
 * integral lines, but objects only need to be word-aligned.  Allocation
 * of word-aligned space is performed by shash_alloc().  Where possible,
 * this allocates from a line already owned by this process.  If it
 * needs to acquire a new line, and the new line happens to abut one
 * already owned (which happens if no other process allocated space in
 * the intervening time), it will take advantage of the contiguous region.
 *
 * When a writer has finished allocating space, it must call
 * shash_done_alloc().  This attempts to return for reallocation any
 * complete lines unused, and in any case throws away any unused partial
 * line.  The latter is what makes calling this a must: once content
 * in a line is published, the line must not be further written to.
 * Returning unused lines is only possible if no other process has since
 * allocated any space.
 *
 * The conditional behaviour that depends on no other process having
 * allocated space is all likely to occur.  The time window for another
 * process to intervene is quite small.  This conditionality is all
 * based on the structure of space allocation in the data file, which
 * uses a next-allocation pointer.
 *
 * FUTURE: should have a shash_prealloc() function that acquires space
 * ready for allocation, with writers estimating how much space they'll
 * use, to minimise activity on the nextalloc pointer and maximise the
 * chances of lines abutting to allow objects to straddle the boundary.
 *
 * FUTURE: should be able to reuse space allocated for a write that was
 * aborted (due to root pointer conditional swap not happening, or due
 * to operation being interrupted by exception).  Allocated space that
 * may have had objects written to it but not published can go back to
 * the prealloc pool, or to the data file's pool.
 */

#define NULL_PTR (~(word)0)
#define ZEROPAD_PTR ((word)DHD_ZEROPAD)
#define ENDDHD_PTR ((word)DHD_SZ)
#define PTR_FLAG_ROLLOVER ((word)1)

#define pointer_loc(sh, ptr, sp) THX_pointer_loc(aTHX_ sh, ptr, sp)
static word *THX_pointer_loc(pTHX_ struct shash *sh, word ptr, word *spc_p)
{
	word ds = sh->data_size;
	if(!likely(IS_WORD_ALIGNED(ptr))) shash_error_data(sh);
	if(unlikely(ptr >= ds)) shash_error_data(sh);
	*spc_p = ds - ptr;
	return &WORD_AT(sh->data_mmap, ptr);
}

#define shash_ensure_data_file(sh) THX_shash_ensure_data_file(aTHX_ sh)
static void THX_shash_ensure_data_file(pTHX_ struct shash *sh)
{
	word datafileid;
	char data_filename[DATA_FILENAME_BUFSIZE];
	int data_fd;
	closefd_ref_t fdr;
	struct stat statbuf;
	SV *mapsv;
	SSize_t old_tmps_floor;
	datafileid = sync_read_word(&WORD_AT(sh->u.live.master_mmap,
					MFL_CURRENT_DATAFILEID));
	if(likely(mapsv = sh->data_mmap_sv)) {
		if(likely(datafileid == sh->u.live.data_file_id)) return;
		sh->data_mmap_sv = NULL;
		SvREFCNT_dec(mapsv);
	}
	sh->u.live.prealloc_len = 0;
	attempt_to_open_data:
	if(unlikely(datafileid == 0)) {
		char *map;
		Newxz(map, PAGE_ALIGN(DHD_SZ + WORD_SZ), char);
		WORD_AT(map, DHD_MAGIC) = DATA_FILE_MAGIC;
		WORD_AT(map, DHD_PARAM) = PARAMETER_WORD;
		WORD_AT(map, DHD_LENGTH) = PAGE_ALIGN(DHD_SZ + WORD_SZ);
		WORD_AT(map, DHD_NEXTALLOC_SPACE) =
			PAGE_ALIGN(DHD_SZ + WORD_SZ);
		WORD_AT(map, DHD_CURRENT_ROOT) = ENDDHD_PTR | PTR_FLAG_ROLLOVER;
		mapsv = newSV_type(SVt_PV);
		SvPV_set(mapsv, map);
		SvLEN_set(mapsv, PAGE_ALIGN(DHD_SZ + WORD_SZ));
		sh->data_mmap = map;
		sh->data_mmap_sv = mapsv;
		sh->data_size = PAGE_ALIGN(DHD_SZ + WORD_SZ);
		sh->u.live.data_file_id = 0;
		return;
	}
	dir_make_data_filename(data_filename, datafileid);
	data_fd = openat(sh->u.live.dir_fd, data_filename,
			((sh->mode & STOREMODE_WRITE) ? O_RDWR : O_RDONLY)
			| O_CLOEXEC);
	if(unlikely(data_fd == -1)) {
		word newdatafileid;
		if(unlikely(errno != ENOENT)) shash_error_errno(sh, "use");
		newdatafileid = sync_read_word(&WORD_AT(sh->u.live.master_mmap,
						MFL_CURRENT_DATAFILEID));
		if(likely(newdatafileid != datafileid)) {
			datafileid = newdatafileid;
			goto attempt_to_open_data;
		}
		shash_error_data(sh);
	}
	fdr = closefd_save(data_fd);
	if(unlikely(fstat(data_fd, &statbuf) == -1))
		shash_error_errno(sh, "use");
	if(!likely(S_ISREG(statbuf.st_mode) && 
			statbuf.st_size >= (off_t)DHD_SZ &&
			(off_t)(word)statbuf.st_size == statbuf.st_size &&
			IS_PAGE_ALIGNED(statbuf.st_size)))
		shash_error_data(sh);
	sh->data_size = statbuf.st_size;
	old_tmps_floor = PL_tmps_floor;
	SAVETMPS;
	mapsv = mmap_as_sv(data_fd, sh->data_size,
			!!(sh->mode & STOREMODE_WRITE));
	if(!likely(mapsv)) shash_error_errno(sh, "use");
	sh->u.live.data_file_id = datafileid;
	sh->data_mmap_sv = SvREFCNT_inc(mapsv);
	sh->data_mmap = mmap_addr_from_sv(mapsv);
	FREETMPS;
	PL_tmps_floor = old_tmps_floor;
	closefd_early(fdr);
	if(!likely(WORD_AT(sh->data_mmap, DHD_MAGIC) == DATA_FILE_MAGIC &&
			WORD_AT(sh->data_mmap, DHD_PARAM) == PARAMETER_WORD &&
			WORD_AT(sh->data_mmap, DHD_LENGTH) == sh->data_size))
		shash_error_data(sh);
}

#define shash_error_toobig(sh) THX_shash_error_toobig(aTHX_ sh)
static void THX_shash_error_toobig(pTHX_ struct shash *sh)
	__attribute__noreturn__;
static void THX_shash_error_toobig(pTHX_ struct shash *sh)
{
	shash_error(sh, "write", "data too large for a shared hash");
}

#define shash_alloc(sh, fjb, len, pp) THX_shash_alloc(aTHX_ sh, fjb, len, pp)
static word *THX_shash_alloc(pTHX_ struct shash *sh, jmp_buf *fulljb, word len,
	word *ptr_p)
{
	byte *loc;
	word wlen = WORD_ALIGN(len);
	if(!likely(wlen) && unlikely(len)) shash_error_toobig(sh);
	if(likely(wlen > sh->u.live.prealloc_len)) {
		byte *prealloc_end =
			sh->u.live.prealloc_loc + sh->u.live.prealloc_len;
		word llen = LINE_ALIGN(wlen);
		word *nextalloc_p =
			&WORD_AT(sh->data_mmap, DHD_NEXTALLOC_SPACE);
		word data_size = sh->data_size;
		if(!likely(llen)) shash_error_toobig(sh);
		while(1) {
			word pos = sync_read_word(nextalloc_p), epos;
			if(unlikely(!IS_LINE_ALIGNED(pos) || pos > data_size))
				shash_error_data(sh);
			epos = pos + llen;
			if(unlikely(epos < pos || epos > data_size)) {
				if(likely(fulljb)) longjmp(*fulljb, 1);
				shash_error_errnum(sh, "write", ENOSPC);
			}
			if(likely(__sync_bool_compare_and_swap(nextalloc_p,
					pos, epos))) {
				byte *newalloc_loc =
					&BYTE_AT(sh->data_mmap, pos);
				if(likely(newalloc_loc == prealloc_end)) {
					sh->u.live.prealloc_len += llen;
				} else {
					sh->u.live.prealloc_loc = newalloc_loc;
					sh->u.live.prealloc_len = llen;
				}
				break;
			}
		}
	}
	loc = sh->u.live.prealloc_loc;
	sh->u.live.prealloc_loc += wlen;
	sh->u.live.prealloc_len -= wlen;
	*ptr_p = loc - (byte*)sh->data_mmap;
	return (word*)loc;
}

#define shash_done_alloc(sh) THX_shash_done_alloc(aTHX_ sh)
static void THX_shash_done_alloc(pTHX_ struct shash *sh)
{
	word chucklen = sh->u.live.prealloc_len & ((1<<LINE_SZ_LOG2)-1);
	sh->u.live.prealloc_loc += chucklen;
	sh->u.live.prealloc_len -= chucklen;
	if(likely(sh->u.live.prealloc_len != 0)) {
		word lowpos = sh->u.live.prealloc_loc - (byte*)sh->data_mmap;
		word highpos = lowpos + sh->u.live.prealloc_len;
		word *nextalloc_p =
			&WORD_AT(sh->data_mmap, DHD_NEXTALLOC_SPACE);
		if(likely(sync_read_word(nextalloc_p) == highpos &&
				__sync_bool_compare_and_swap(nextalloc_p,
					highpos, lowpos)))
			sh->u.live.prealloc_len = 0;
	}
}

/* strings in the shash */

#define string_as_pv(sh, ptr, len_p) THX_string_as_pv(aTHX_ sh, ptr, len_p)
static char const *THX_string_as_pv(pTHX_ struct shash *sh, word ptr,
	word *len_p)
{
	word len, *loc, spc, alloclen;
	char *pv;
	loc = pointer_loc(sh, ptr, &spc);
	len = loc[0];
	alloclen = len + WORD_SZ+1;
	if(unlikely(alloclen < WORD_SZ+1 || alloclen > spc))
		shash_error_data(sh);
	pv = (char*)&loc[1];
	if(unlikely(pv[len])) shash_error_data(sh);
	*len_p = len;
	return pv;
}

static MGVTBL const mgvtbl_mmapref;

#define string_as_sv(sh, ptr) THX_string_as_sv(aTHX_ sh, ptr)
static SV *THX_string_as_sv(pTHX_ struct shash *sh, word ptr)
{
	word len;
	char const *pv = string_as_pv(sh, ptr, &len);
	SV *sv;
	if(unlikely((word)(STRLEN)len != len))
		shash_error_errnum(sh, "read", ENOMEM);
	/*
	 * There are two strategies available for returning the string
	 * as an SV.  We can copy into a plain string SV, or we can point
	 * into the mmaped space.  In the latter case the result SV needs
	 * magic to keep a reference to the object representing the mmap,
	 * to keep it mapped.  In both time and memory, the overhead of
	 * pointing into the mmap is pretty much fixed, but the overhead
	 * of copying is roughly linear in the length of the string.
	 * The base overhead for copying is much less than the fixed
	 * overhead of mapping.
	 *
	 * We therefore want to copy short strings and map long strings.
	 * Choosing the threshold at which to switch is a black art.
	 *
	 * Empirical result for perl 5.16 on amd64 with glibc 2.11
	 * is that 119-octet strings are better copied and 120-octet
	 * strings are better mapped, with a sharp step in the cost of
	 * copying at that length.  This is presumably due to the memory
	 * allocator switching strategy when allocating 128 octets or more
	 * (rounded up from 120+1).
	 *
	 * The memory allocations of interest are one XPV and the
	 * buffer for copying, and one XPVMG and one MAGIC for mapping.
	 * The ugly expression here tries to compare the two sets of
	 * allocations.  The XPVMG+MAGIC - XPV difference is compared
	 * against the potential buffer size.  It is presumed that the
	 * buffer length will be rounded up to a word-aligned size.
	 * The structure size difference is rounded up in an attempt to
	 * find a threshold likely to be used by the memory allocator.
	 * Ideally this would be rounded to the next power of 2, but we
	 * can't implement that in a constant expression, so it's actually
	 * rounded to the next multiple of the XPVMG size.  The formula
	 * is slightly contrived so as to achieve the exact 120-octet
	 * threshold on the amd64 system used for speed trials (where
	 * MAGIC is 40 octets, XPV is 32 octets, and XPVMG is 64 octets).
	 *
	 * FUTURE: timing results for significantly different systems,
	 * especially a 32-bit architecture, should be used to refine
	 * this formula.
	 */
	if(len < sizeof(XPVMG) *
			((sizeof(MAGIC)+sizeof(XPVMG)*2-1) / sizeof(XPVMG)) -
			sizeof(size_t)) {
		sv = sv_2mortal(newSVpvn(pv, len));
	} else {
		sv = sv_2mortal(newSV_type(SVt_PVMG));
		(void) sv_magicext(sv, sh->data_mmap_sv, PERL_MAGIC_ext,
					&mgvtbl_mmapref, NULL, 0);
		SvPV_set(sv, (char*)pv);
		SvCUR_set(sv, len);
		SvPOK_on(sv);
	}
	SvREADONLY_on(sv);
	return sv;
}

#define string_cmp_sv(sh, aptr, bsv) THX_string_cmp_sv(aTHX_ sh, aptr, bsv)
static int THX_string_cmp_sv(pTHX_ struct shash *sh, word aptr, SV *bsv)
{
	word alen;
	STRLEN blen;
	char const *apv = string_as_pv(sh, aptr, &alen);
	char const *bpv = SvPV(bsv, blen);
	if(unlikely(SvUTF8(bsv))) {
		if(unlikely((word)(STRLEN)alen != alen))
			shash_error_errnum(sh, "use", ENOMEM);
		return bytes_cmp_utf8((U8*)apv, alen, (U8*)bpv, blen);
	} else {
		int r;
		if(unlikely((word)(size_t)alen != alen))
			shash_error_errnum(sh, "use", ENOMEM);
		r = memcmp(apv, bpv, alen < blen ? alen : blen);
		return r ? r : alen == blen ? 0 : alen < blen ? -1 : 1;
	}
}

#define string_write_from_pv(sh, fjb, pv, len, u8) \
	THX_string_write_from_pv(aTHX_ sh, fjb, pv, len, u8)
static word THX_string_write_from_pv(pTHX_ struct shash *sh, jmp_buf *fulljb,
	char const *pv, word rawlen, bool is_utf8)
{
	if(unlikely(rawlen == 0) && DHD_ZEROPAD_SZ >= WORD_SZ+1)
		return ZEROPAD_PTR;
	if(unlikely(is_utf8)) {
		word reallen;
		word alloclen, ptr, *loc;
		byte *q;
		char const *end = pv + rawlen, *p;
		for(reallen = 0, p = pv; p != end; reallen++, p++) {
			U8 c = (U8)*p;
			if(unlikely(c & 0x80)) {
				if(!likely((c == 0xc2 || c == 0xc3) &&
						(((U8)*++p) & 0xc0) == 0x80))
					croak("can't put non-octet string "
						"into shared hash");
			}
		}
		if(reallen == rawlen) goto pv_in_octet_form;
		alloclen = reallen + WORD_SZ + 1;
		if(unlikely(alloclen < WORD_SZ+1)) shash_error_toobig(sh);
		loc = shash_alloc(sh, fulljb, alloclen, &ptr);
		loc[0] = reallen;
		for(p = pv, q = (byte*)&loc[1]; p != end; p++, q++) {
			U8 c = (U8)*p;
			if(unlikely(c & 0x80))
				c = ((c & 0x03) << 6) | (((U8)*++p) & 0x3f);
			*q = (byte)c;
		}
		*q = 0;
		return ptr;
	} else {
		word alloclen, ptr, *loc;
		pv_in_octet_form:
		alloclen = rawlen + WORD_SZ + 1;
		if(unlikely(alloclen < WORD_SZ+1)) shash_error_toobig(sh);
		loc = shash_alloc(sh, fulljb, alloclen, &ptr);
		loc[0] = rawlen;
		(void) memcpy(&loc[1], pv, rawlen);
		((byte*)&loc[1])[rawlen] = 0;
		return ptr;
	}
}

#define string_write_from_sv(sh, fjb, sv) \
	THX_string_write_from_sv(aTHX_ sh, fjb, sv)
static word THX_string_write_from_sv(pTHX_ struct shash *sh, jmp_buf *fulljb,
	SV *sv)
{
	STRLEN rawlen;
	char const *pv = SvPV(sv, rawlen);
	if(unlikely((STRLEN)(word)rawlen != rawlen)) shash_error_toobig(sh);
	return string_write_from_pv(sh, fulljb, pv, rawlen, !!SvUTF8(sv));
}

#define string_size(sh, ptr) THX_string_size(aTHX_ sh, ptr)
static word THX_string_size(pTHX_ struct shash *sh, word ptr)
{
	word spc;
	word len = pointer_loc(sh, ptr, &spc)[0];
	if(unlikely(len == 0) && DHD_ZEROPAD_SZ >= WORD_SZ+1)
		return 0;
	return WORD_ALIGN(len + WORD_SZ+1);
}

#define string_migrate(shf, ptrf, sht) THX_string_migrate(aTHX_ shf, ptrf, sht)
static word THX_string_migrate(pTHX_ struct shash *shf, word ptrf,
	struct shash *sht)
{
	word len;
	char const *pv = string_as_pv(shf, ptrf, &len);
	return string_write_from_pv(sht, NULL, pv, len, 0);
}

/*
 * btrees in the shash
 *
 * This code is a bit spaghetti-ish, in the attempt to produce reasonably
 * efficient machine code.  You are expected to already understand how
 * a btree operates.
 *
 * Things are a bit asymmetric because we're only caching lower bound
 * keys in the btree nodes.  If a key of interest precedes the first
 * key in the shash, this becomes immediately obvious at the root node.
 * Having compared against the boundary keys at a parent node means that
 * in a child node there is no need to compare against its first cached
 * key.  We start any search by comparing the key of interest against
 * the first lower bound key at the root node, so that comparisons
 * thereafter consistently don't need to compare against any node's
 * first lower bound.
 *
 * When inserting into the btree, by using the same search mechanism we
 * always end up inserting subnodes after some existing subnode, except
 * in the necessary special case where the key of interest precedes the
 * first key in the shash.
 */

#define LAYER_MAX 0x3f
#define bnode_header_layer(h) ((h) & LAYER_MAX)
#define bnode_header_splay(h) (((h) >> 8) & BYTE_MAX)
#define bnode_header_pad(h) ((h) & WORD_C(0xffffffffffff00c0))
#define bnode_body_loc(loc) (&(loc)[1])

#define bnode_check(sh, np, el, lp, sp) \
	THX_bnode_check(aTHX_ sh, np, el, lp, sp)
static word const *THX_bnode_check(pTHX_ struct shash *sh, word ptr,
	int expect_layer, int *layer_p, int *splay_p)
{
	word header, spc;
	word const *loc;
	int layer, splay;
	loc = pointer_loc(sh, ptr, &spc);
	header = loc[0];
	layer = bnode_header_layer(header);
	splay = bnode_header_splay(header);
	if(unlikely(bnode_header_pad(header) || splay > MAXSPLAY ||
			spc < WORD_SZ + (((size_t)splay) << (WORD_SZ_LOG2+1))))
		shash_error_data(sh);
	if(unlikely(expect_layer == -1)) {
		if(unlikely(splay < 2 && layer != 0)) shash_error_data(sh);
	} else {
		if(unlikely(layer != expect_layer || splay < MINSPLAY))
			shash_error_data(sh);
	}
	*layer_p = layer;
	*splay_p = splay;
	return loc;
}

#define BNODE_SEARCH_EXACT INT_MIN

#define bnode_search(sh, nl, sp, ksv) THX_bnode_search(aTHX_ sh, nl, sp, ksv)
static int THX_bnode_search(pTHX_ struct shash *sh, word const *loc,
	int splay, SV *keysv)
{
	int l, r;
	word const *nodebody = bnode_body_loc(loc);
	for(l = 0, r = splay-1; l != r; ) {
		/* binary search invariant:
		 * search key > lower bount of subnode [l]
		 * search key < upper bound of subnode [r]
		 */
		int m = (l+r+1) >> 1;
		int cmpm = string_cmp_sv(sh, nodebody[m << 1], keysv);
		if(unlikely(cmpm == 0)) {
			return BNODE_SEARCH_EXACT | m;
		} else if(cmpm > 0) {
			r = m-1;
		} else {
			l = m;
		}
	}
	return l;
}

#define bnode_write(sh, fjb, nh, ne, nb) \
	THX_bnode_write(aTHX_ sh, fjb, nh, ne, nb)
static word THX_bnode_write(pTHX_ struct shash *sh, jmp_buf *fulljb,
	int layer, int splay, word const *nodebody)
{
	word ptr, *loc;
	if(unlikely(splay == 0) && likely(layer == 0) &&
			DHD_ZEROPAD_SZ >= WORD_SZ)
		return ZEROPAD_PTR;
	loc = shash_alloc(sh, fulljb, WORD_SZ + (splay << (WORD_SZ_LOG2+1)),
		&ptr);
	loc[0] = layer | (splay << 8);
	(void) memcpy(&loc[1], nodebody, splay << (WORD_SZ_LOG2+1));
	return ptr;
}

#define btree_get(sh, rt, keysv) THX_btree_get(aTHX_ sh, rt, keysv)
static word THX_btree_get(pTHX_ struct shash *sh, word root, SV *keysv)
{
	int layer = -1, pos = 0;
	word ptr = root;
	word const *ndloc;
	while(1) {
		int nlayer, nsplay;
		ndloc = bnode_check(sh, ptr, layer, &nlayer, &nsplay);
		if(unlikely(layer == -1)) {
			int cmp0;
			layer = nlayer;
			if(unlikely(nsplay == 0)) return NULL_PTR;
			cmp0 = string_cmp_sv(sh, bnode_body_loc(ndloc)[0],
				keysv);
			if(unlikely(cmp0 > 0)) return NULL_PTR;
			if(unlikely(cmp0 == 0)) goto exact_match;
		}
		pos = bnode_search(sh, ndloc, nsplay, keysv);
		if(unlikely(pos & BNODE_SEARCH_EXACT))
			goto exact_match;
		if(unlikely(layer == 0)) return NULL_PTR;
		ptr = bnode_body_loc(ndloc)[(pos<<1)+1];
		layer--;
	}
	exact_match:
	ptr = bnode_body_loc(ndloc)[((pos&~BNODE_SEARCH_EXACT)<<1)+1];
	while(layer) {
		int nlayer, nsplay;
		layer--;
		ndloc = bnode_check(sh, ptr, layer, &nlayer, &nsplay);
		ptr = bnode_body_loc(ndloc)[1];
	}
	return ptr;
}

#define btree_set(sh, fjb, rt, keysv, valsv) \
	THX_btree_set(aTHX_ sh, fjb, rt, keysv, valsv)
static word THX_btree_set(pTHX_ struct shash *sh, jmp_buf *fulljb,
	word oldroot, SV *keysv, SV *valsv)
{
	word const *nodeloc[LAYER_MAX+1];
	byte nodesplay[LAYER_MAX+1];
	byte index[LAYER_MAX+1];
	int layer = -1, root_layer = -1;
	word keyptr, valptr, ndptr = oldroot;
	word const *ndloc;
	int ntorm, ntoin;
	word inakey, inaval, inbkey = 0, inbval = 0;
	word nodebody[(MAXSPLAY+MINSPLAY-1)*2];
	while(1) {
		int nlayer, nsplay, pos;
		ndloc = bnode_check(sh, ndptr, layer, &nlayer, &nsplay);
		if(unlikely(layer == -1)) layer = root_layer = nlayer;
		nodeloc[layer] = ndloc;
		nodesplay[layer] = nsplay;
		if(unlikely(layer == root_layer)) {
			int cmp0;
			if(unlikely(nsplay == 0)) {
				index[0] = (byte)-1;
				goto inexact_match;
			}
			cmp0 = string_cmp_sv(sh, bnode_body_loc(ndloc)[0],
				keysv);
			if(unlikely(cmp0 > 0)) {
				while(layer) {
					index[layer] = 0;
					ndptr = bnode_body_loc(ndloc)[1];
					layer--;
					ndloc = bnode_check(sh, ndptr, layer,
							&nlayer, &nsplay);
					nodeloc[layer] = ndloc;
					nodesplay[layer] = nsplay;
				}
				index[0] = (byte)-1;
				goto inexact_match;
			}
			if(unlikely(cmp0 == 0)) {
				index[layer] = 0;
				goto exact_match;
			}
		}
		pos = bnode_search(sh, ndloc, nsplay, keysv);
		index[layer] = pos & ~BNODE_SEARCH_EXACT;
		if(unlikely(pos & BNODE_SEARCH_EXACT)) goto exact_match;
		if(unlikely(layer == 0)) goto inexact_match;
		ndptr = bnode_body_loc(ndloc)[(pos<<1)+1];
		layer--;
	}
	exact_match:
	keyptr = bnode_body_loc(ndloc)[index[layer]<<1];
	ndptr = bnode_body_loc(ndloc)[(index[layer]<<1)+1];
	while(layer) {
		int nlayer, nsplay;
		layer--;
		ndloc = bnode_check(sh, ndptr, layer, &nlayer, &nsplay);
		nodeloc[layer] = ndloc;
		nodesplay[layer] = nsplay;
		index[layer] = 0;
		ndptr = bnode_body_loc(ndloc)[1];
	}
	valptr = ndptr;
	if(!SvOK(valsv)) {
		/* delete */
		ntorm = 1;
		ntoin = 0;
		goto modify;
	} else {
		/* modify */
		if(string_cmp_sv(sh, valptr, valsv) == 0) return oldroot;
		ntorm = 1;
		ntoin = 1;
		inakey = keyptr;
		inaval = string_write_from_sv(sh, fulljb, valsv);
		goto modify;
	}
	inexact_match:
	if(!SvOK(valsv)) {
		/* no-op delete */
		return oldroot;
	} else {
		/* insert */
		index[0]++;
		ntorm = 0;
		ntoin = 1;
		inakey = string_write_from_sv(sh, fulljb, keysv);
		inaval = string_write_from_sv(sh, fulljb, valsv);
		goto modify;
	}
	modify:
	do {
		word const *ndloc = nodeloc[layer];
		int nsplay = nodesplay[layer], modpos = index[layer];
		(void) memcpy(nodebody, bnode_body_loc(ndloc),
			modpos << (WORD_SZ_LOG2+1));
		if(likely(ntoin)) {
			nodebody[modpos<<1] = inakey;
			nodebody[(modpos<<1)+1] = inaval;
			if(unlikely(ntoin > 1)) {
				nodebody[(modpos<<1)+2] = inbkey;
				nodebody[(modpos<<1)+3] = inbval;
			}
		}
		(void) memcpy(nodebody + ((modpos+ntoin)<<1),
			bnode_body_loc(ndloc) + ((modpos+ntorm)<<1),
			(nsplay-(modpos+ntorm)) << (WORD_SZ_LOG2+1));
		nsplay = nsplay - ntorm + ntoin;
		if(likely(nsplay >= MINSPLAY)) {
			ntorm = 1;
		} else {
			word const *upndloc;
			int uppos;
			if(likely(layer == root_layer)) {
				if(unlikely(nsplay == 1) && likely(layer != 0))
					return nodebody[1];
				return bnode_write(sh, fulljb, layer, nsplay,
					nodebody);
			}
			ntorm = 2;
			upndloc = nodeloc[layer+1];
			uppos = index[layer+1];
			if(likely(uppos + 1 != nodesplay[layer+1])) {
				int adjnlayer, adjnsplay;
				word adjndptr =
					bnode_body_loc(upndloc)[(uppos<<1) + 3];
				word const *adjndloc =
					bnode_check(sh, adjndptr, layer,
						&adjnlayer, &adjnsplay);
				(void) memcpy(nodebody + (nsplay<<1),
					bnode_body_loc(adjndloc),
					adjnsplay << (WORD_SZ_LOG2+1));
				nsplay += adjnsplay;
			} else {
				int adjnlayer, adjnsplay;
				word adjndptr;
				word const *adjndloc;
				index[layer+1] = uppos - 1;
				adjndptr =
					bnode_body_loc(upndloc)[(uppos<<1) - 1];
				adjndloc = bnode_check(sh, adjndptr, layer,
						&adjnlayer, &adjnsplay);
				(void) memmove(nodebody + (adjnsplay<<1),
					nodebody, nsplay << (WORD_SZ_LOG2+1));
				(void) memcpy(nodebody,
					bnode_body_loc(adjndloc),
					adjnsplay << (WORD_SZ_LOG2+1));
				nsplay += adjnsplay;
			}
		}
		if(unlikely(nsplay > MAXSPLAY)) {
			int splitpos = nsplay >> 1;
			inakey = nodebody[0];
			inaval = bnode_write(sh, fulljb, layer, splitpos,
					nodebody);
			inbkey = nodebody[splitpos << 1];
			inbval = bnode_write(sh, fulljb, layer, nsplay-splitpos,
					nodebody + (splitpos<<1));
			ntoin = 2;
		} else {
			inakey = nodebody[0];
			inaval = bnode_write(sh, fulljb, layer, nsplay,
					nodebody);
			ntoin = 1;
		}
	} while(layer++ != root_layer);
	if(likely(ntoin == 1)) return inaval;
	if(unlikely(layer == LAYER_MAX+1)) shash_error_toobig(sh);
	nodebody[0] = inakey;
	nodebody[1] = inaval;
	nodebody[2] = inbkey;
	nodebody[3] = inbval;
	return bnode_write(sh, fulljb, layer, 2, nodebody);
}

#define btree_size_at_layer(sh, np, el) \
	THX_btree_size_at_layer(aTHX_ sh, np, el)
static word THX_btree_size_at_layer(pTHX_ struct shash *sh, word ptr,
	int expect_layer);
static word THX_btree_size_at_layer(pTHX_ struct shash *sh, word ptr,
	int expect_layer)
{
	int layer, splay, i;
	word const *loc = bnode_check(sh, ptr, expect_layer, &layer, &splay);
	word sz;
	if(unlikely(splay == 0) && likely(layer == 0) &&
			DHD_ZEROPAD_SZ >= WORD_SZ)
		return 0;
	sz = WORD_SZ + (splay << (WORD_SZ_LOG2+1));
	loc = bnode_body_loc(loc);
	if(likely(layer == 0)) {
		for(i = splay << 1; i--; ) {
			word asz = string_size(sh, *loc++);
			sz += asz;
			if(sz < asz) return ~(word)0;
		}
	} else {
		layer--;
		for(i = splay; i--; ) {
			word asz = btree_size_at_layer(sh, loc[1], layer);
			sz += asz;
			if(sz < asz) return ~(word)0;
			loc += 2;
		}
	}
	return sz;
}

#define btree_size(sh, rt) THX_btree_size(aTHX_ sh, rt)
static word THX_btree_size(pTHX_ struct shash *sh, word root)
{
	return btree_size_at_layer(sh, root, -1);
}

#define btree_migrate_at_layer(shf, ptrf, el, sht) \
	THX_btree_migrate_at_layer(aTHX_ shf, ptrf, el, sht)
static word THX_btree_migrate_at_layer(pTHX_ struct shash *shf, word ptrf,
	int expect_layer, struct shash *sht)
{
	int layer, splay, i;
	word nodebody[MAXSPLAY*2];
	word const *locf = bnode_body_loc(bnode_check(shf, ptrf, expect_layer,
							&layer, &splay));
	word *loct = nodebody;
	if(likely(layer == 0)) {
		for(i = splay << 1; i--; ) {
			*loct++ = string_migrate(shf, *locf++, sht);
		}
	} else {
		for(i = splay; i--; ) {
			word spc;
			word ptrt = btree_migrate_at_layer(shf, locf[1],
					layer-1, sht);
			locf += 2;
			*loct++ =
				bnode_body_loc(pointer_loc(sht, ptrt, &spc))[0];
			*loct++ = ptrt;
		}
	}
	return bnode_write(sht, NULL, layer, splay, nodebody);
}

#define btree_migrate(shf, ptrf, sht) THX_btree_migrate(aTHX_ shf, ptrf, sht)
static word THX_btree_migrate(pTHX_ struct shash *shf, word ptrf,
	struct shash *sht)
{
	return btree_migrate_at_layer(shf, ptrf, -1, sht);
}

/* mechanism for reading from shash */

#define shash_root_for_read(sh) THX_shash_root_for_read(aTHX_ sh)
static word THX_shash_root_for_read(pTHX_ struct shash *sh)
{
	if(sh->mode & STOREMODE_SNAPSHOT) {
		return sh->u.snapshot.root;
	} else {
		shash_ensure_data_file(sh);
		return sync_read_word(&WORD_AT(sh->data_mmap,
					DHD_CURRENT_ROOT)) &
			~PTR_FLAG_ROLLOVER;
	}
}

/* mechanism for writing to shash */

#define shash_initiate_rollover(sh) THX_shash_initiate_rollover(aTHX_ sh)
static void THX_shash_initiate_rollover(pTHX_ struct shash *sh)
{
	word *root_p = &WORD_AT(sh->data_mmap, DHD_CURRENT_ROOT);
	while(1) {
		word root = sync_read_word(root_p);
		if(unlikely(root & PTR_FLAG_ROLLOVER)) break;
		if(likely(__sync_bool_compare_and_swap(root_p,
				root, root | PTR_FLAG_ROLLOVER)))
			break;
	}
}

#define shash_do_rollover(sh, addsz) THX_shash_do_rollover(aTHX_ sh, addsz)
static word THX_shash_do_rollover(pTHX_ struct shash *sh, word addsz)
{
	char filename[DATA_FILENAME_BUFSIZE];
	word *allocfileid_p;
	word old_file_id, old_root, new_file_id, new_root, new_sz;
	int new_fd;
	unlinkfile_ref_t new_ulr;
	closefd_ref_t new_fdr;
	struct shash new_sh;
	SV *old_mmap_sv;
	SSize_t old_tmps_floor;
	old_root = sync_read_word(&WORD_AT(sh->data_mmap, DHD_CURRENT_ROOT)) &
			~PTR_FLAG_ROLLOVER;
	new_sz = DHD_SZ + btree_size(sh, old_root);
	if(unlikely(new_sz < DHD_SZ || (new_sz & (((word)7) << 61))))
		shash_error_toobig(sh);
	new_sz <<= 3;
	new_sz += addsz;
	if(unlikely(new_sz < addsz)) shash_error_toobig(sh);
	new_sz = PAGE_ALIGN(new_sz);
	if(unlikely(!new_sz)) shash_error_toobig(sh);
	if(unlikely((word)(off_t)new_sz != new_sz))
		shash_error_errnum(sh, "write", EFBIG);
	new_sh.top_pathname_sv = sh->top_pathname_sv;
	new_sh.u.live.prealloc_loc = NULL;
	new_sh.u.live.prealloc_len = 0;
	allocfileid_p =
		&WORD_AT(sh->u.live.master_mmap, MFL_LASTALLOC_DATAFILEID);
	do {
		old_file_id = sync_read_word(allocfileid_p);
		new_file_id = old_file_id + 1;
		if(unlikely(new_file_id == 0)) new_file_id = 1;
	} while(!likely(__sync_bool_compare_and_swap(allocfileid_p,
				old_file_id, new_file_id)));
	dir_make_data_filename(filename, new_file_id);
	new_fd = openat(sh->u.live.dir_fd, filename,
		O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0666);
	if(unlikely(new_fd == -1)) shash_error_errno(sh, "write");
	new_ulr = unlinkfile_save(sh->u.live.dir_fd, filename);
	new_fdr = closefd_save(new_fd);
	if(unlikely(ftruncate(new_fd, (off_t)new_sz) == -1))
		shash_error_errno(sh, "write");
	old_tmps_floor = PL_tmps_floor;
	SAVETMPS;
	new_sh.data_mmap_sv = mmap_as_sv(new_fd, new_sz, 1);
	if(!new_sh.data_mmap_sv) shash_error_errno(sh, "write");
	new_sh.data_mmap = mmap_addr_from_sv(new_sh.data_mmap_sv);
	new_sh.data_size = new_sz;
	closefd_early(new_fdr);
	WORD_AT(new_sh.data_mmap, DHD_MAGIC) = DATA_FILE_MAGIC;
	WORD_AT(new_sh.data_mmap, DHD_PARAM) = PARAMETER_WORD;
	WORD_AT(new_sh.data_mmap, DHD_LENGTH) = new_sz;
	WORD_AT(new_sh.data_mmap, DHD_NEXTALLOC_SPACE) = DHD_SZ;
	WORD_AT(new_sh.data_mmap, DHD_CURRENT_ROOT) = new_root =
		btree_migrate(sh, old_root, &new_sh);
	shash_done_alloc(&new_sh);
	old_file_id = sh->u.live.data_file_id;
	if(!likely(__sync_bool_compare_and_swap(&WORD_AT(sh->u.live.master_mmap,
							MFL_CURRENT_DATAFILEID),
			old_file_id, new_file_id))) {
		unlinkfile_early(new_ulr);
		FREETMPS;
		PL_tmps_floor = old_tmps_floor;
		return NULL_PTR;
	}
	unlinkfile_cancel(new_ulr);
	old_mmap_sv = sh->data_mmap_sv;
	sh->data_mmap_sv = NULL;
	SvREFCNT_dec(old_mmap_sv);
	sh->data_mmap_sv = SvREFCNT_inc(new_sh.data_mmap_sv);
	sh->data_mmap = new_sh.data_mmap;
	sh->data_size = new_sh.data_size;
	sh->u.live.data_file_id = new_file_id;
	sh->u.live.prealloc_loc = NULL;
	sh->u.live.prealloc_len = 0;
	FREETMPS;
	PL_tmps_floor = old_tmps_floor;
	if(old_file_id != 0) {
		dir_make_data_filename(filename, old_file_id);
		(void) unlinkat(sh->u.live.dir_fd, filename, 0);
	}
	dir_clean(sh, new_file_id);
	return new_root;
}

#define shash_mutate(sh, mut, marg) THX_shash_mutate(aTHX_ sh, mut, marg)
static void THX_shash_mutate(pTHX_ struct shash *sh,
	word (*THX_mutate)(pTHX_ struct shash *sh, jmp_buf *fulljb,
		word oldroot, void *mutate_arg),
	void *mutate_arg)
{
	jmp_buf fulljb;
	volatile word addsz = PAGE_ALIGN(1<<20);
	volatile bool just_rolled_over = 0;
	if(unlikely(setjmp(fulljb))) {
		if(unlikely(just_rolled_over)) {
			word newaddsz = addsz <<= 1;
			if(!likely(newaddsz)) shash_error_toobig(sh);
		}
		shash_initiate_rollover(sh);
	}
	while(1) {
		word old_root, new_root;
		just_rolled_over = 0;
		shash_ensure_data_file(sh);
		old_root = sync_read_word(&WORD_AT(sh->data_mmap,
						DHD_CURRENT_ROOT));
		if(unlikely(old_root & PTR_FLAG_ROLLOVER)) {
			old_root = shash_do_rollover(sh, addsz);
			if(unlikely(old_root == NULL_PTR)) continue;
			just_rolled_over = 1;
		}
		new_root = THX_mutate(aTHX_ sh, &fulljb, old_root, mutate_arg);
		if(likely(new_root == old_root) ||
				likely(__sync_bool_compare_and_swap(
					&WORD_AT(sh->data_mmap,
						DHD_CURRENT_ROOT),
					old_root, new_root)))
			break;
	}
}

/* shash opening and creation */

#define mode_from_sv(sv) THX_mode_from_sv(aTHX_ sv)
static unsigned THX_mode_from_sv(pTHX_ SV *modesv)
{
	char const *modepv, *modeend, *p;
	STRLEN modelen;
	unsigned mode = 0;
	if(!likely(sv_is_string(modesv))) croak("mode is not a string");
	modepv = SvPV(modesv, modelen);
	modeend = modepv + modelen;
	for(p = modepv; p != modeend; p++) {
		char c = *p;
		unsigned f;
		switch(c) {
			case 'r': f = STOREMODE_READ; break;
			case 'w': f = STOREMODE_WRITE; break;
			case 'c': f = STOREMODE_CREATE; break;
			case 'e': f = STOREMODE_EXCLUDE; break;
			default: {
				f = 0;
				if(likely(c >= ' ' && c <= '~'))
					croak("unknown open mode flag `%c'", c);
				else
					croak("unknown open mode flag");
			}
		}
		if(unlikely(mode & f))
			croak("duplicate open mode flag `%c'", c);
		mode |= f;
	}
	return mode;
}

#define mode_as_sv(m) THX_mode_as_sv(aTHX_ m)
static SV *THX_mode_as_sv(pTHX_ unsigned mode)
{
	char buf[4], *p;
	SV *modesv;
	p = buf;
	if(likely(mode & STOREMODE_READ)) *p++ = 'r';
	if(likely(mode & STOREMODE_WRITE)) *p++ = 'w';
	if(unlikely(mode & STOREMODE_CREATE)) *p++ = 'c';
	if(unlikely(mode & STOREMODE_EXCLUDE)) *p++ = 'e';
	modesv = sv_2mortal(newSVpvn(buf, p - buf));
	SvREADONLY_on(modesv);
	return modesv;
}

#define shash_open_error_magic(sh) THX_shash_open_error_magic(aTHX_ sh)
static void THX_shash_open_error_magic(pTHX_ struct shash *sh)
	__attribute__noreturn__;
static void THX_shash_open_error_magic(pTHX_ struct shash *sh)
{
	shash_error(sh, "open", "not a shared hash");
}

static void THX_shash_open_check_file(pTHX_ struct shash *sh, char const *fn,
	word arg)
{
	PERL_UNUSED_ARG(arg);
	word id;
	if(unlikely(dir_filename_class(fn, &id) == FILENAME_CLASS_BOGUS))
		shash_open_error_magic(sh);
}

#define shash_open(psv, mfl) THX_shash_open(aTHX_ psv, mfl)
static SV *THX_shash_open(pTHX_ SV *top_pathname_sv, unsigned mode)
{
	char const *top_pathname_pv;
	struct shash *sh;
	SV *shsv, *shsvref, *mapsv;
	int open_mode =
		((mode & STOREMODE_WRITE) ? O_RDWR : O_RDONLY) | O_CLOEXEC;
	int dir_fd, master_fd;
	struct stat statbuf;
	unlinkfile_ref_t ulr;
	char temp_filename[TEMP_FILENAME_BUFSIZE];
	closefd_ref_t fdr;
	void *map;
	shsv = newSV_type(SVt_PVMG);
	shsvref = sv_2mortal(newRV_noinc(shsv));
	Newxz(sh, 1, struct shash);
	sh->u.live.dir_fd = -1;
	SvPV_set(shsv, (char *)sh);
	SvLEN_set(shsv, sizeof(struct shash));
	(void) sv_bless(shsvref, shash_handle_stash);
	sh->mode = mode & (STOREMODE_READ|STOREMODE_WRITE);
	sh->top_pathname_sv = newSVsv(top_pathname_sv);
	top_pathname_pv = SvPV_nolen(sh->top_pathname_sv);
	sh->u.live.dir_fd = dir_fd = open(top_pathname_pv, O_RDONLY|O_CLOEXEC);
	if(unlikely(dir_fd == -1)) {
		if(!likely(errno == ENOENT && (mode & STOREMODE_CREATE)))
			shash_error_errno(sh, "open");
		if(unlikely(mkdir(top_pathname_pv, 0777) == -1) &&
				errno != EEXIST)
			shash_error_errno(sh, "open");
		sh->u.live.dir_fd = dir_fd =
			open(top_pathname_pv, O_RDONLY|O_CLOEXEC);
		if(unlikely(dir_fd == -1))
			shash_error_errno(sh, "open");
	}
	if(unlikely(fstat(dir_fd, &statbuf) == -1))
		shash_error_errno(sh, "open");
	if(!likely(S_ISDIR(statbuf.st_mode)))
		shash_open_error_magic(sh);
	dir_iterate(sh, "open", THX_shash_open_check_file, 0);
	master_fd = openat(dir_fd, MASTER_FILENAME, open_mode);
	if(likely(master_fd != -1)) {
		closefd_ref_t fdr;
		SV *mapsv;
		opened_master:
		fdr = closefd_save(master_fd);
		if(unlikely(mode & STOREMODE_EXCLUDE))
			shash_error_errnum(sh, "open", EEXIST);
		if(unlikely(fstat(master_fd, &statbuf) == -1))
			shash_error_errno(sh, "open");
		if(!likely(S_ISREG(statbuf.st_mode) &&
				statbuf.st_size == MFL_SZ))
			shash_open_error_magic(sh);
		mapsv = mmap_as_sv(master_fd, MFL_SZ,
				!!(mode & STOREMODE_WRITE));
		if(!likely(mapsv)) shash_error_errno(sh, "open");
		sh->u.live.master_mmap_sv = SvREFCNT_inc(mapsv);
		sh->u.live.master_mmap = mmap_addr_from_sv(mapsv);
		closefd_early(fdr);
		if(!likely(WORD_AT(sh->u.live.master_mmap, MFL_MAGIC) ==
					MASTER_FILE_MAGIC))
			shash_open_error_magic(sh);
		if(!likely(WORD_AT(sh->u.live.master_mmap, MFL_PARAM) ==
					PARAMETER_WORD))
			shash_error(sh, "open", "unsupported format");
		if(mode & STOREMODE_WRITE)
			dir_clean(sh, sync_read_word(
					&WORD_AT(sh->u.live.master_mmap,
						MFL_CURRENT_DATAFILEID)));
		return shsvref;
	}
	if(!likely(errno == ENOENT && (mode & STOREMODE_CREATE)))
		shash_error_errno(sh, "open");
	master_fd = dir_make_temp_file(sh, temp_filename);
	if(unlikely(master_fd == -1)) shash_error_errno(sh, "open");
	ulr = unlinkfile_save(dir_fd, temp_filename);
	fdr = closefd_save(master_fd);
	if(unlikely(ftruncate(master_fd, MFL_SZ) == -1))
		shash_error_errno(sh, "open");
	mapsv = mmap_as_sv(master_fd, MFL_SZ, 1);
	if(!likely(mapsv)) shash_error_errno(sh, "open");
	sh->u.live.master_mmap_sv = SvREFCNT_inc(mapsv);
	sh->u.live.master_mmap = map = mmap_addr_from_sv(mapsv);
	closefd_early(fdr);
	WORD_AT(map, MFL_MAGIC) = MASTER_FILE_MAGIC;
	WORD_AT(map, MFL_PARAM) = PARAMETER_WORD;
	if(unlikely(linkat(dir_fd, temp_filename, dir_fd, MASTER_FILENAME, 0)
			== -1)) {
		if(unlikely(errno != EEXIST))
			shash_error_errno(sh, "open");
		mmap_early_unmap(mapsv);
		sh->u.live.master_mmap_sv = NULL;
		SvREFCNT_dec(mapsv);
		unlinkfile_early(ulr);
		master_fd = openat(dir_fd, MASTER_FILENAME, open_mode);
		if(unlikely(master_fd == -1)) shash_error_errno(sh, "open");
		goto opened_master;
	}
	unlinkfile_early(ulr);
	dir_clean(sh, 0);
	return shsvref;
}

/*
 * API operations in base pp form
 *
 * These functions take a fixed number of arguments from the Perl stack,
 * and put their mortal result on the stack.  At the C level they take no
 * arguments other than the Perl context and return no value.  This is not
 * the format used for actual pp_ functions, which implement ops, as those
 * interact with PL_op.  Nor is it the format used for XS function bodies,
 * which take a variable number of arguments delimited by a stack mark.
 * These pp1_ functions are the parts of the operations that are common
 * to ops and XS functions.
 *
 * FUTURE: should support atomic operations on a group of multiple
 * specific keys and on a lexicographical range of keys.  A group of
 * multiple keys is supplied as the keys of a hash.  It suffices for a
 * range to be specified by an inclusive lower bound and an exclusive
 * upper bound, with undef permitted to impose no bound; an exclusive
 * lower bound or inclusive upper bound can be arranged by the caller
 * appending "\0" to the key.  The same operations can be supported
 * that are supported on a single key, simply operating on all the keys
 * in parallel.  Additionally, a conditional set can be grouped, using a
 * single condition across all keys rather than a separate condition for
 * each key.  Other operations that can be performed on a group/range are
 * to check whether any keys exist (single truth-value result for whole
 * group/range), count extant keys, list extant keys in lexicographical
 * order, and find first/last extant key.
 *
 * FUTURE: group write operations should be implemented by btree
 * merging, rather than by repeated single-key modifications.  Group read
 * operations also could benefit from specific support.  It may make sense
 * to reformulate single-key operations as groups of unit cardinality.
 */

#define arg_check_key(arg) THX_arg_check_key(aTHX_ arg)
static void THX_arg_check_key(pTHX_ SV *arg)
{
	if(!likely(sv_is_string(arg))) croak("key is not a string");
}

#define arg_check_value(role, arg) THX_arg_check_value(aTHX_ role, arg)
static void THX_arg_check_value(pTHX_ char const *role, SV *arg)
{
	if(!likely(sv_is_undef(arg) || sv_is_string(arg)))
		croak("%s value is neither a string nor undef", role);
}

#define pp1_is_shash() THX_pp1_is_shash(aTHX)
static void THX_pp1_is_shash(pTHX)
{
	dSP;
	SETs(bool_sv(arg_is_shash(TOPs)));
}

#define pp1_check_shash() THX_pp1_check_shash(aTHX)
static void THX_pp1_check_shash(pTHX)
{
	dSP;
	arg_check_shash(POPs);
	if(unlikely(GIMME_V == G_SCALAR)) PUSHs(&PL_sv_undef);
	PUTBACK;
}

#define pp1_shash_open() THX_pp1_shash_open(aTHX)
static void THX_pp1_shash_open(pTHX)
{
	SV *sh;
	dSP;
	SV *modesv = POPs;
	SV *top_pathname_sv = TOPs;
	PUTBACK;
	sh = shash_open(top_pathname_sv, mode_from_sv(modesv));
	SPAGAIN;
	SETs(sh);
}

#define pp1_shash_is_readable() THX_pp1_shash_is_readable(aTHX)
static void THX_pp1_shash_is_readable(pTHX)
{
	dSP;
	SETs(bool_sv(shash_from_svref(TOPs)->mode & STOREMODE_READ));
}

#define pp1_shash_is_writable() THX_pp1_shash_is_writable(aTHX)
static void THX_pp1_shash_is_writable(pTHX)
{
	dSP;
	SETs(bool_sv(shash_from_svref(TOPs)->mode & STOREMODE_WRITE));
}

#define pp1_shash_mode() THX_pp1_shash_mode(aTHX)
static void THX_pp1_shash_mode(pTHX)
{
	dSP;
	SETs(mode_as_sv(shash_from_svref(TOPs)->mode));
}

#define pp1_shash_getd() THX_pp1_shash_getd(aTHX)
static void THX_pp1_shash_getd(pTHX)
{
	SV *resultsv;
	dSP;
	SV *keysv = POPs;
	struct shash *sh = shash_from_svref(TOPs);
	PUTBACK;
	arg_check_key(keysv);
	shash_check_readable(sh);
	resultsv = bool_sv(btree_get(sh, shash_root_for_read(sh), keysv)
				!= NULL_PTR);
	SPAGAIN;
	SETs(resultsv);
}

#define pp1_shash_get() THX_pp1_shash_get(aTHX)
static void THX_pp1_shash_get(pTHX)
{
	SV *valsv;
	word valptr;
	dSP;
	SV *keysv = POPs;
	struct shash *sh = shash_from_svref(TOPs);
	PUTBACK;
	arg_check_key(keysv);
	shash_check_readable(sh);
	valptr = btree_get(sh, shash_root_for_read(sh), keysv);
	valsv = valptr == NULL_PTR ? &PL_sv_undef : string_as_sv(sh, valptr);
	SPAGAIN;
	SETs(valsv);
}

struct mutateargs_set {
	SV *keysv;
	SV *newvalsv;
};

static word THX_mutate_set(pTHX_ struct shash *sh, jmp_buf *fulljb,
	word oldroot, void *mutate_arg)
{
	struct mutateargs_set *args = (struct mutateargs_set *)mutate_arg;
	return btree_set(sh, fulljb, oldroot, args->keysv, args->newvalsv);
}

#define pp1_shash_set() THX_pp1_shash_set(aTHX)
static void THX_pp1_shash_set(pTHX)
{
	struct mutateargs_set args;
	struct shash *sh;
	dSP;
	args.newvalsv = POPs;
	args.keysv = POPs;
	sh = shash_from_svref(POPs);
	if(unlikely(GIMME_V == G_SCALAR)) PUSHs(&PL_sv_undef);
	PUTBACK;
	arg_check_key(args.keysv);
	arg_check_value("new", args.newvalsv);
	shash_check_writable(sh);
	shash_mutate(sh, THX_mutate_set, &args);
	shash_done_alloc(sh);
}

#define pp1_shash_tied_store() THX_pp1_shash_tied_store(aTHX)
static void THX_pp1_shash_tied_store(pTHX)
{
	dSP;
	arg_check_shash(SP[-2]);
	arg_check_key(SP[-1]);
	if(!likely(sv_is_string(SP[0]))) croak("new value is not a string");
	pp1_shash_set();
}

struct mutateargs_gset {
	SV *keysv;
	SV *newvalsv;
	word oldvalptr;
};

static word THX_mutate_gset(pTHX_ struct shash *sh, jmp_buf *fulljb,
	word oldroot, void *mutate_arg)
{
	struct mutateargs_gset *args = (struct mutateargs_gset *)mutate_arg;
	args->oldvalptr = btree_get(sh, oldroot, args->keysv);
	return btree_set(sh, fulljb, oldroot, args->keysv, args->newvalsv);
}

#define pp1_shash_gset() THX_pp1_shash_gset(aTHX)
static void THX_pp1_shash_gset(pTHX)
{
	SV *oldvalsv;
	struct mutateargs_gset args;
	struct shash *sh;
	dSP;
	args.newvalsv = POPs;
	args.keysv = POPs;
	sh = shash_from_svref(TOPs);
	PUTBACK;
	arg_check_key(args.keysv);
	arg_check_value("new", args.newvalsv);
	shash_check_readable(sh);
	shash_check_writable(sh);
	shash_mutate(sh, THX_mutate_gset, &args);
	shash_done_alloc(sh);
	oldvalsv = args.oldvalptr == NULL_PTR ? &PL_sv_undef :
					string_as_sv(sh, args.oldvalptr);
	SPAGAIN;
	SETs(oldvalsv);
}

#define pp1_shash_tied_delete() THX_pp1_shash_tied_delete(aTHX)
static void THX_pp1_shash_tied_delete(pTHX)
{
	dSP;
	XPUSHs(&PL_sv_undef);
	PUTBACK;
	pp1_shash_gset();
}

struct mutateargs_cset {
	SV *keysv;
	SV *chkvalsv;
	SV *newvalsv;
	bool result;
};

static word THX_mutate_cset(pTHX_ struct shash *sh, jmp_buf *fulljb,
	word oldroot, void *mutate_arg)
{
	struct mutateargs_cset *args = (struct mutateargs_cset *)mutate_arg;
	word oldvalptr = btree_get(sh, oldroot, args->keysv);
	if(!likely(!SvOK(args->chkvalsv) ? oldvalptr == NULL_PTR :
			oldvalptr != NULL_PTR &&
			string_cmp_sv(sh, oldvalptr, args->chkvalsv) == 0)) {
		args->result = 0;
		return oldroot;
	}
	args->result = 1;
	return btree_set(sh, fulljb, oldroot, args->keysv, args->newvalsv);
}

#define pp1_shash_cset() THX_pp1_shash_cset(aTHX)
static void THX_pp1_shash_cset(pTHX)
{
	struct mutateargs_cset args;
	struct shash *sh;
	dSP;
	args.newvalsv = POPs;
	args.chkvalsv = POPs;
	args.keysv = POPs;
	sh = shash_from_svref(TOPs);
	PUTBACK;
	arg_check_key(args.keysv);
	arg_check_value("check", args.chkvalsv);
	arg_check_value("new", args.newvalsv);
	shash_check_readable(sh);
	shash_check_writable(sh);
	shash_mutate(sh, THX_mutate_cset, &args);
	shash_done_alloc(sh);
	SPAGAIN;
	SETs(bool_sv(args.result));
}

#define pp1_shash_snapshot() THX_pp1_shash_snapshot(aTHX)
static void THX_pp1_shash_snapshot(pTHX)
{
	SV *snapshsvref;
	dSP;
	SV *shsvref = TOPs;
	struct shash *sh = shash_from_svref(shsvref);
	if(unlikely(sh->mode & STOREMODE_SNAPSHOT)) {
		snapshsvref = sv_mortalcopy(shsvref);
	} else {
		word root = shash_root_for_read(sh);
		struct shash *snapsh;
		SV *snapshsv;
		snapshsv = newSV_type(SVt_PVMG);
		snapshsvref = sv_2mortal(newRV_noinc(snapshsv));
		Newxz(snapsh, 1, struct shash);
		SvPV_set(snapshsv, (char *)snapsh);
		SvLEN_set(snapshsv, sizeof(struct shash));
		(void) sv_bless(snapshsvref, shash_handle_stash);
		snapsh->top_pathname_sv = SvREFCNT_inc(sh->top_pathname_sv);
		snapsh->mode =
			(sh->mode & ~STOREMODE_WRITE) | STOREMODE_SNAPSHOT;
		snapsh->data_mmap_sv = SvREFCNT_inc(sh->data_mmap_sv);
		snapsh->data_mmap = sh->data_mmap;
		snapsh->data_size = sh->data_size;
		snapsh->u.snapshot.root = root;
	}
	SETs(snapshsvref);
}

#define pp1_shash_is_snapshot() THX_pp1_shash_is_snapshot(aTHX)
static void THX_pp1_shash_is_snapshot(pTHX)
{
	dSP;
	SETs(bool_sv(shash_from_svref(TOPs)->mode & STOREMODE_SNAPSHOT));
}

/* API operations in pp form for ops */

#define HSM_MAKE_PP(name) \
	static OP *THX_pp_##name(pTHX) \
	{ \
		pp1_##name(); \
		return NORMAL; \
	}

HSM_MAKE_PP(is_shash)
HSM_MAKE_PP(check_shash)
HSM_MAKE_PP(shash_open)
HSM_MAKE_PP(shash_is_readable)
HSM_MAKE_PP(shash_is_writable)
HSM_MAKE_PP(shash_mode)
HSM_MAKE_PP(shash_getd)
HSM_MAKE_PP(shash_get)
HSM_MAKE_PP(shash_set)
HSM_MAKE_PP(shash_gset)
HSM_MAKE_PP(shash_cset)
HSM_MAKE_PP(shash_snapshot)
HSM_MAKE_PP(shash_is_snapshot)

/* API operations as XS function bodies */

#define HSM_MAKE_XSFUNC(name, arity, argnames) \
	static void THX_xsfunc_##name(pTHX_ CV *cv) \
	{ \
		dMARK; dSP; \
		if(unlikely(SP - MARK != arity)) croak_xs_usage(cv, argnames); \
		pp1_##name(); \
	}

HSM_MAKE_XSFUNC(is_shash, 1, "arg")
HSM_MAKE_XSFUNC(check_shash, 1, "arg")
HSM_MAKE_XSFUNC(shash_open, 2, "filename, mode")
HSM_MAKE_XSFUNC(shash_is_readable, 1, "shash")
HSM_MAKE_XSFUNC(shash_is_writable, 1, "shash")
HSM_MAKE_XSFUNC(shash_mode, 1, "shash")
HSM_MAKE_XSFUNC(shash_getd, 2, "shash, key")
HSM_MAKE_XSFUNC(shash_get, 2, "shash, key")
HSM_MAKE_XSFUNC(shash_set, 3, "shash, key, newvalue")
HSM_MAKE_XSFUNC(shash_tied_store, 3, "shash, key, newvalue")
HSM_MAKE_XSFUNC(shash_gset, 3, "shash, key, newvalue")
HSM_MAKE_XSFUNC(shash_tied_delete, 2, "shash, key")
HSM_MAKE_XSFUNC(shash_cset, 4, "shash, key, chkvalue, newvalue")
HSM_MAKE_XSFUNC(shash_snapshot, 1, "shash")
HSM_MAKE_XSFUNC(shash_is_snapshot, 1, "shash")

/* checker to turn function calls into custom ops */

static OP *THX_ck_entersub_args_hsm(pTHX_ OP *entersubop, GV *namegv, SV *ckobj)
{
	CV *cv = (CV*)ckobj;
	OP *pushop, *firstargop, *cvop, *lastargop, *argop, *newop;
	int nargs;
	pushop = cUNOPx(entersubop)->op_first;
	if(!pushop->op_sibling) pushop = cUNOPx(pushop)->op_first;
	firstargop = pushop->op_sibling;
	for (cvop = firstargop; cvop->op_sibling; cvop = cvop->op_sibling) ;
	lastargop = pushop;
	for (nargs = 0, lastargop = pushop, argop = firstargop; argop != cvop;
			nargs++, lastargop = argop, argop = argop->op_sibling)
		(void) op_contextualize(argop, G_SCALAR);
	if(unlikely(nargs != (int)CvPROTOLEN(cv)))
		return ck_entersub_args_proto(entersubop, namegv, (SV*)cv);
	pushop->op_sibling = cvop;
	lastargop->op_sibling = NULL;
	op_free(entersubop);
	newop = newUNOP(OP_CUSTOM, 0, firstargop);
	newop->op_ppaddr = DPTR2FPTR(Perl_ppaddr_t, CvXSUBANY(cv).any_ptr);
	return newop;
}

MODULE = Hash::SharedMem PACKAGE = Hash::SharedMem

PROTOTYPES: DISABLE

BOOT:
{
	shash_handle_stash = gv_stashpvs("Hash::SharedMem::Handle", 1);
}

BOOT:
{
#define HSM_FUNC_TO_INSTALL(name, arity) \
		{ \
			"Hash::SharedMem::"#name, \
			THX_pp_##name, \
			THX_xsfunc_##name, \
			(arity), \
		}
	struct {
		char const *fqsubname;
		Perl_ppaddr_t THX_pp;
		XSUBADDR_t THX_xsfunc;
		int arity;
	} const funcs_to_install[] = {
		HSM_FUNC_TO_INSTALL(is_shash, 1),
		HSM_FUNC_TO_INSTALL(check_shash, 1),
		HSM_FUNC_TO_INSTALL(shash_open, 2),
		HSM_FUNC_TO_INSTALL(shash_is_readable, 1),
		HSM_FUNC_TO_INSTALL(shash_is_writable, 1),
		HSM_FUNC_TO_INSTALL(shash_mode, 1),
		HSM_FUNC_TO_INSTALL(shash_getd, 2),
		HSM_FUNC_TO_INSTALL(shash_get, 2),
		HSM_FUNC_TO_INSTALL(shash_set, 3),
		HSM_FUNC_TO_INSTALL(shash_gset, 3),
		HSM_FUNC_TO_INSTALL(shash_cset, 4),
		HSM_FUNC_TO_INSTALL(shash_snapshot, 1),
		HSM_FUNC_TO_INSTALL(shash_is_snapshot, 1),
	}, *fti;
	int i;
	for(i = C_ARRAY_LENGTH(funcs_to_install); i--; ) {
		XOP *xop;
		char const *shortname;
		CV *cv;
		fti = &funcs_to_install[i];
		Newxz(xop, 1, XOP);
		shortname = fti->fqsubname + sizeof("Hash::SharedMem::")-1;
		XopENTRY_set(xop, xop_name, shortname);
		XopENTRY_set(xop, xop_desc, shortname);
		XopENTRY_set(xop, xop_class, OA_UNOP);
		Perl_custom_op_register(aTHX_ fti->THX_pp, xop);
		cv = newXSproto_portable(fti->fqsubname, fti->THX_xsfunc,
			__FILE__, "$$$$"+4-fti->arity);
		CvXSUBANY(cv).any_ptr = FPTR2DPTR(void*, fti->THX_pp);
		cv_set_call_checker(cv, THX_ck_entersub_args_hsm, (SV*)cv);
	}
}

MODULE = Hash::SharedMem PACKAGE = Hash::SharedMem::Handle

PROTOTYPES: DISABLE

void
DESTROY(SV *shash)
PREINIT:
	struct shash *sh;
CODE:
	sh = shash_from_svref(shash);
	if(!(sh->mode & STOREMODE_SNAPSHOT)) {
		if(unlikely(sh->u.live.prealloc_len)) shash_done_alloc(sh);
		if(likely(sh->u.live.master_mmap_sv))
			SvREFCNT_dec(sh->u.live.master_mmap_sv);
		if(likely(sh->u.live.dir_fd != -1)) close(sh->u.live.dir_fd);
	}
	if(likely(sh->top_pathname_sv)) SvREFCNT_dec(sh->top_pathname_sv);
	if(likely(sh->data_mmap_sv)) SvREFCNT_dec(sh->data_mmap_sv);

SV *
open(SV *classname, SV *filename, SV *mode)
CODE:
	PERL_UNUSED_VAR(classname);
	PUTBACK;
	RETVAL = shash_open(filename, mode_from_sv(mode));
	(void) SvREFCNT_inc(RETVAL);
	SPAGAIN;
OUTPUT:
	RETVAL

BOOT:
{
	HV *fstash = gv_stashpvs("Hash::SharedMem", 0);
	HV *mstash = gv_stashpvs("Hash::SharedMem::Handle", 0);
	HE *he;
	for(hv_iterinit(fstash); (he = hv_iternext(fstash)); ) {
		STRLEN klen;
		char const *kpv = HePV(he, klen);
		if(klen > 6 && memcmp(kpv, "shash_", 6) == 0 &&
				!(klen == 10 && memcmp(kpv+6, "open", 4) == 0))
			(void) hv_store(mstash, kpv+6, klen-6,
					SvREFCNT_inc(HeVAL(he)), 0);
	}
}

SV *
TIEHASH(SV *classname, SV *arg0, SV *arg1 = NULL)
CODE:
	PERL_UNUSED_VAR(classname);
	if(!arg1) {
		arg_check_shash(arg0);
		RETVAL = newSVsv(arg0);
	} else {
		PUTBACK;
		RETVAL = shash_open(arg0, mode_from_sv(arg1));
		(void) SvREFCNT_inc(RETVAL);
		SPAGAIN;
	}
OUTPUT:
	RETVAL

void
CLEAR(SV *shash)
PPCODE:
	arg_check_shash(shash);
	croak("can't clear shared hash");

void
FIRSTKEY(SV *shash)
PPCODE:
	arg_check_shash(shash);
	croak("can't enumerate shared hash");

void
NEXTKEY(SV *shash, SV *lastkey)
PPCODE:
	arg_check_shash(shash);
	arg_check_key(lastkey);
	croak("can't enumerate shared hash");

void
SCALAR(SV *shash)
PPCODE:
	arg_check_shash(shash);
	croak("can't check occupancy of shared hash");

BOOT:
{
	HV *mstash = gv_stashpvs("Hash::SharedMem::Handle", 0);
	(void) hv_stores(mstash, "EXISTS",
		SvREFCNT_inc(*hv_fetchs(mstash, "getd", 0)));
	(void) hv_stores(mstash, "FETCH",
		SvREFCNT_inc(*hv_fetchs(mstash, "get", 0)));
	(void) newXSproto_portable("Hash::SharedMem::Handle::STORE",
		THX_xsfunc_shash_tied_store, __FILE__, "$$$");
	(void) newXSproto_portable("Hash::SharedMem::Handle::DELETE",
		THX_xsfunc_shash_tied_delete, __FILE__, "$$");
}
