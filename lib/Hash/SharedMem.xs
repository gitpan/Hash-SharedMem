#define PERL_NO_GET_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "callchecker0.h"
#include <sys/mman.h>

/* Perl compatibility */

#define PERL_VERSION_DECIMAL(r,v,s) (r*1000000 + v*1000 + s)
#define PERL_DECIMAL_VERSION \
	PERL_VERSION_DECIMAL(PERL_REVISION,PERL_VERSION,PERL_SUBVERSION)
#define PERL_VERSION_GE(r,v,s) \
	(PERL_DECIMAL_VERSION >= PERL_VERSION_DECIMAL(r,v,s))

#ifndef EXPECT
# ifdef __GNUC__
#  define EXPECT(e, v) __builtin_expect(e, v)
# else /* !__GNUC__ */
#  define EXPECT(e, v) (e)
# endif /* !__GNUC__ */
#endif /* !EXPECT */

#define likely(t) EXPECT(!!(t), 1)
#define unlikely(t) EXPECT(!!(t), 0)

#ifndef __attribute__noreturn__
# ifdef __GNUC__
#  define __attribute__noreturn__ __attribute__((noreturn))
# else /* !__GNUC__ */
#  define __attribute__noreturn__ /**/
# endif /* !__GNUC__ */
#endif /* !__attribute__noreturn__ */

#ifndef C_ARRAY_LENGTH
# define C_ARRAY_LENGTH(a) (sizeof(a)/sizeof(*(a)))
#endif /* !C_ARRAY_LENGTH */

#ifndef PERL_STATIC_INLINE
# define PERL_STATIC_INLINE static
#endif /* !PERL_STATIC_INLINE */

#ifndef PERL_UNUSED_VAR
# define PERL_UNUSED_VAR(x) ((void)x)
#endif /* !PERL_UNUSED_VAR */

#ifndef PERL_UNUSED_ARG
# define PERL_UNUSED_ARG(x) PERL_UNUSED_VAR(x)
#endif /* !PERL_UNUSED_ARG */

#ifndef DPTR2FPTR
# define DPTR2FPTR(t,x) ((t)(UV)(x))
#endif /* !DPTR2FPTR */

#ifndef FPTR2DPTR
# define FPTR2DPTR(t,x) ((t)(UV)(x))
#endif /* !FPTR2DPTR */

#ifndef Newx
# define Newx(v,n,t) New(0,v,n,t)
#endif /* !Newx */

#ifndef Newxz
# define Newxz(v,n,t) Newz(0,v,n,t)
#endif /* !Newxz */

#ifndef ptr_table_new

struct q_ptr_tbl_ent {
	struct q_ptr_tbl_ent *next;
	void *from, *to;
};

# undef PTR_TBL_t
# define PTR_TBL_t struct q_ptr_tbl_ent *

# define ptr_table_new() THX_ptr_table_new(aTHX)
PERL_STATIC_INLINE PTR_TBL_t *THX_ptr_table_new(pTHX)
{
	PTR_TBL_t *tbl;
	Newx(tbl, 1, PTR_TBL_t);
	*tbl = NULL;
	return tbl;
}

# if 0
#  define ptr_table_free(tbl) THX_ptr_table_free(aTHX_ tbl)
PERL_STATIC_INLINE void THX_ptr_table_free(pTHX_ PTR_TBL_t *tbl)
{
	struct q_ptr_tbl_ent *ent = *tbl;
	Safefree(tbl);
	while(ent) {
	        struct q_ptr_tbl_ent *nent = ent->next;
	        Safefree(ent);
	        ent = nent;
	}
}
# endif /* 0 */

# define ptr_table_store(tbl, from, to) THX_ptr_table_store(aTHX_ tbl, from, to)
PERL_STATIC_INLINE void THX_ptr_table_store(pTHX_ PTR_TBL_t *tbl, void *from,
	void *to)
{
	struct q_ptr_tbl_ent *ent;
	Newx(ent, 1, struct q_ptr_tbl_ent);
	ent->next = *tbl;
	ent->from = from;
	ent->to = to;
	*tbl = ent;
}

# define ptr_table_fetch(tbl, from) THX_ptr_table_fetch(aTHX_ tbl, from)
PERL_STATIC_INLINE void *THX_ptr_table_fetch(pTHX_ PTR_TBL_t *tbl, void *from)
{
	struct q_ptr_tbl_ent *ent;
	for(ent = *tbl; ent; ent = ent->next) {
	        if(ent->from == from) return ent->to;
	}
	return NULL;
}

#endif /* !ptr_table_new */

#ifndef SvREFCNT_inc_NN
# define SvREFCNT_inc_NN SvREFCNT_inc
#endif /* !SvREFCNT_inc_NN */

#ifndef SvREFCNT_inc_simple
# define SvREFCNT_inc_simple SvREFCNT_inc
#endif /* !SvREFCNT_inc_simple */

#ifndef SvREFCNT_inc_simple_NN
# define SvREFCNT_inc_simple_NN SvREFCNT_inc_NN
#endif /* !SvREFCNT_inc_simple_NN */

#ifndef SvREFCNT_inc_void
# define SvREFCNT_inc_void(sv) ((void) SvREFCNT_inc(sv))
#endif /* !SvREFCNT_inc_void */

#ifndef SvREFCNT_inc_void_NN
# define SvREFCNT_inc_void_NN(sv) ((void) SvREFCNT_inc_NN(sv))
#endif /* !SvREFCNT_inc_void_NN */

#ifndef SvREFCNT_inc_simple_void
# define SvREFCNT_inc_simple_void(sv) ((void) SvREFCNT_inc_simple(sv))
#endif /* !SvREFCNT_inc_simple_void */

#ifndef SvREFCNT_inc_simple_void_NN
# define SvREFCNT_inc_simple_void_NN(sv) ((void) SvREFCNT_inc_simple_NN(sv))
#endif /* !SvREFCNT_inc_simple_void_NN */

#ifndef SvREFCNT_dec_NN
# define SvREFCNT_dec_NN SvREFCNT_dec
#endif /* !SvREFCNT_dec_NN */

#ifndef SvUV_set
# define SvUV_set(sv, uv) (SvUVX(sv) = (uv))
#endif /* !SvUV_set */

#ifndef CvPROTO
# define CvPROTO(cv) SvPVX((SV*)(cv))
# define CvPROTOLEN(cv) SvCUR((SV*)(cv))
#endif /* !CvPROTO */

#ifndef SvMAGIC_set
# define SvMAGIC_set(sv, mg) (SvMAGIC(sv) = (mg))
#endif /* !SvMAGIC_set */

#ifndef PERL_MAGIC_ext
# define PERL_MAGIC_ext '~'
#endif /* !PERL_MAGIC_ext */

#ifndef sv_magicext
# define sv_magicext(sv, obj, type, vtbl, name, namlen) \
	THX_sv_magicext(aTHX_ sv, obj, type, vtbl, name, namlen)
static MAGIC *THX_sv_magicext(pTHX_ SV *sv, SV *obj, int type,
	MGVTBL const *vtbl, char const *name, I32 namlen)
{
	MAGIC *mg;
	PERL_UNUSED_ARG(name);
	PERL_UNUSED_ARG(namlen);
	Newxz(mg, 1, MAGIC);
	mg->mg_virtual = (MGVTBL*)vtbl;
	mg->mg_type = type;
	if(likely(obj)) {
		mg->mg_obj = SvREFCNT_inc_simple_NN(obj);
		mg->mg_flags |= MGf_REFCOUNTED;
	}
	(void) SvUPGRADE(sv, SVt_PVMG);
	mg->mg_moremagic = SvMAGIC(sv);
	SvMAGIC_set(sv, mg);
	SvMAGICAL_off(sv);
	mg_magical(sv);
	return mg;
}
#endif /* !sv_magicext */

#ifndef sv_unmagicext
# define sv_unmagicext(sv, type, vtbl) THX_sv_unmagicext(aTHX_ sv, type, vtbl)
PERL_STATIC_INLINE int THX_sv_unmagicext(pTHX_ SV *sv, int type,
	MGVTBL const *vtbl)
{
	MAGIC *mg, **mgp;
	if(SvTYPE(sv) < SVt_PVMG || !SvMAGIC(sv)) return 0;
	mgp = NULL;
	for(mg = SvMAGIC(sv); mg; mg = unlikely(mgp) ? *mgp : SvMAGIC(sv)) {
		if(likely(mg->mg_type == type && mg->mg_virtual == vtbl)) {
			if(unlikely(mgp))
				*mgp = mg->mg_moremagic;
			else
				SvMAGIC_set(sv, mg->mg_moremagic);
			if(likely(vtbl->svt_free)) vtbl->svt_free(aTHX_ sv, mg);
			if(unlikely(mg->mg_flags & MGf_REFCOUNTED))
				SvREFCNT_dec(mg->mg_obj);
			Safefree(mg);
		} else {
			mgp = &mg->mg_moremagic;
		}
	}
	SvMAGICAL_off(sv);
	mg_magical(sv);
	return 0;
}
#endif /* !sv_unmagicext */

#ifndef newSV_type
# define newSV_type(type) THX_newSV_type(aTHX_ type)
static SV *THX_newSV_type(pTHX_ svtype type)
{
	SV *sv = newSV(0);
	(void) SvUPGRADE(sv, type);
	return sv;
}
#endif /* !newSV_type */

#ifndef gv_stashpvs
# define gv_stashpvs(name, flags) gv_stashpvn(""name"", sizeof(name)-1, flags)
#endif /* !gv_stashpvs */

#ifndef hv_fetchs
# define hv_fetchs(hv, keystr, lval) \
		hv_fetch(hv, ""keystr"", sizeof(keystr)-1, lval)
#endif /* !hv_fetchs */

#ifndef hv_stores
# define hv_stores(hv, keystr, val) \
		hv_store(hv, ""keystr"", sizeof(keystr)-1, val, 0)
#endif /* !hv_stores */

#if !PERL_VERSION_GE(5,9,3)
typedef OP *(*Perl_ppaddr_t)(pTHX);
#endif /* <5.9.3 */

#ifndef SvPV_nomg
# define SvPV_nomg(sv, len) \
	(SvGMAGICAL(sv) ? THX_SvPV_nomg_magical(aTHX_ sv, &(len)) : \
		SvPV(sv, len))
struct remagic {
	SV *sv;
	MAGIC *mg;
};
static void THX_remagic_cleanup(pTHX_ void *remagic_v)
{
	struct remagic remagic = *(struct remagic *)remagic_v;
	Safefree(remagic_v);
	if(unlikely(remagic.sv)) {
		SvMAGIC(remagic.sv) = remagic.mg;
		SvREFCNT_dec_NN(remagic.sv);
	}
}
static char *THX_SvPV_nomg_magical(pTHX_ SV *sv, STRLEN *len_p)
{
	char *pv;
	struct remagic *remagic;
	Newx(remagic, 1, struct remagic);
	remagic->sv = sv;
	remagic->mg = SvMAGIC(sv);
	SAVEDESTRUCTOR_X(THX_remagic_cleanup, remagic);
	SvREFCNT_inc_simple_void_NN(sv);
	SvMAGIC(sv) = NULL;
	pv = SvPV(sv, *len_p);
	SvMAGIC(sv) = remagic->mg;
	SvREFCNT_dec_NN(sv);
	remagic->sv = NULL;
	return pv;
}
#endif /* !SvPV_nomg */

#if PERL_VERSION_GE(5,19,4)
typedef SSize_t tmps_ix_t;
#else /* <5.19.4 */
typedef I32 tmps_ix_t;
#endif /* <5.19.4 */

#ifdef newSVpvn_flags
# define newSVpvn_mortal(pv, len) newSVpvn_flags(pv, len, SVs_TEMP)
#else /* !newSVpvn_flags */
# define newSVpvn_mortal(pv, len) sv_2mortal(newSVpvn(pv, len))
#endif /* !newSVpvn_flags */

/* Perl additions */

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

/* system call compatibility */

#ifndef MAP_FAILED
# define MAP_FAILED ((void*)-1)
#endif /* !MAP_FAILED */

#ifndef FD_CLOEXEC
# define FD_CLOEXEC 1
#endif /* !FD_CLOEXEC */

/*
 * opening with close-on-exec flag
 *
 * When we open file descriptors, we always want the close-on-exec flag
 * set.  Ideally we'd use the thread-safe (and convenient) O_CLOEXEC,
 * but that's not available everywhere.  So the wrappers open_cloexec()
 * and openat_cloexec() encapsulate the job of setting the close-on-exec
 * flag in the best manner possible.
 *
 * Even if the headers define O_CLOEXEC, it might not actually
 * be implemented in the kernel at runtime.  So it is necessary to
 * experiment at runtime to see how to actually get the close-on-exec
 * flag set.  The experiment is run on the first attempts at opening.
 * Experimentation is performed separately for open(2) and openat(2).
 * In any sensible system they'll have identical treatment of the flags,
 * but it's unwise to rely on sensibleness.  We do rely on each syscall
 * being consistent over time, within the scope of a single program run.
 *
 * Kernels that don't support O_CLOEXEC can't be relied upon to object
 * if it's supplied.  Linux, for example, ignores open(2) flags that
 * it doesn't know about.  So the experiment must check the actual flag
 * state if open(2) appears to work.  Anticipating that some other kernel
 * will check the flags, EINVAL is also accepted as an indicator that
 * O_CLOEXEC isn't valid.  Once a definitive experimental result has been
 * obtained, the system switches to one of three concrete strategies:
 * use O_CLOEXEC only (if it worked), use F_SETFD only (if O_CLOEXEC was
 * rejected or didn't work), or use both (if O_CLOEXEC was accepted and
 * F_GETFD failed).
 */

enum {
	CLOEXEC_EXPERIMENT,
	CLOEXEC_AT_OPEN,
	CLOEXEC_AFTER_OPEN,
	CLOEXEC_AT_AND_AFTER_OPEN
};

static int open_cloexec(char const *path, int flags, mode_t mode)
{
#ifdef O_CLOEXEC
	static int strategy = CLOEXEC_EXPERIMENT;
	switch(strategy) {
		case CLOEXEC_EXPERIMENT: default: {
			int fd, fdflags;
			fd = open(path, flags | O_CLOEXEC, mode);
			if(unlikely(fd == -1)) {
				if(unlikely(errno == EINVAL)) {
					strategy = CLOEXEC_AFTER_OPEN;
					goto after_open;
				}
				return -1;
			}
			fdflags = fcntl(fd, F_GETFD);
			if(unlikely(fdflags == -1)) {
				strategy = CLOEXEC_AT_AND_AFTER_OPEN;
				(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			} else if(likely(fdflags & FD_CLOEXEC)) {
				strategy = CLOEXEC_AT_OPEN;
			} else {
				strategy = CLOEXEC_AFTER_OPEN;
				(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			}
			return fd;
		}
		case CLOEXEC_AT_OPEN: {
			return open(path, flags | O_CLOEXEC, mode);
		}
		case CLOEXEC_AFTER_OPEN: after_open: break;
		case CLOEXEC_AT_AND_AFTER_OPEN: {
			int fd = open(path, flags | O_CLOEXEC, mode);
			if(likely(fd != -1))
				(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			return fd;
		}
	}
#endif /* O_CLOEXEC */
	{
		int fd = open(path, flags, mode);
		if(likely(fd != -1)) (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
		return fd;
	}
}

#if QHAVE_OPENAT && QHAVE_FSTATAT && QHAVE_LINKAT && QHAVE_UNLINKAT && \
	QHAVE_FDOPENDIR
static int openat_cloexec(int dirfd, char const *path, int flags, mode_t mode)
{
# ifdef O_CLOEXEC
	static int strategy = CLOEXEC_EXPERIMENT;
	switch(strategy) {
		case CLOEXEC_EXPERIMENT: default: {
			int fd, fdflags;
			fd = openat(dirfd, path, flags | O_CLOEXEC, mode);
			if(unlikely(fd == -1)) {
				if(unlikely(errno == EINVAL)) {
					strategy = CLOEXEC_AFTER_OPEN;
					goto after_open;
				}
				return -1;
			}
			fdflags = fcntl(fd, F_GETFD);
			if(unlikely(fdflags == -1)) {
				strategy = CLOEXEC_AT_AND_AFTER_OPEN;
				(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			} else if(likely(fdflags & FD_CLOEXEC)) {
				strategy = CLOEXEC_AT_OPEN;
			} else {
				strategy = CLOEXEC_AFTER_OPEN;
				(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			}
			return fd;
		}
		case CLOEXEC_AT_OPEN: {
			return openat(dirfd, path, flags | O_CLOEXEC, mode);
		}
		case CLOEXEC_AFTER_OPEN: after_open: break;
		case CLOEXEC_AT_AND_AFTER_OPEN: {
			int fd = openat(dirfd, path, flags | O_CLOEXEC, mode);
			if(likely(fd != -1))
				(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			return fd;
		}
	}
# endif /* O_CLOEXEC */
	{
		int fd = openat(dirfd, path, flags, mode);
		if(likely(fd != -1)) (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
		return fd;
	}
}
#endif

/*
 * file operations relative to referenced directory
 *
 * A directory is preferably referenced by a file descriptor.
 * File operations relative to it are performed by the system calls
 * openat(2), fstatat(2), linkat(2), and unlinkat(2).  This system
 * means that the directory reference remains valid if the directory
 * is renamed, and means that there is a minimum of name resolution.
 * However, these system calls aren't available very widely, so an
 * alternative mechanism is required.
 *
 * The alternative is that an absolute pathname is stored, along with
 * the device number and inode of the directory.  File operations are
 * performed by using full pathnames, immediately after checking that
 * the stored directory pathname still refers to the correct directory.
 * If the directory is moved, operations will start failing.
 *
 * Which system to use is in the general case determined at runtime,
 * because even with calls to the modern system calls compiling, there's
 * no guarantee that the running kernel is one that supports them.
 * We therefore experiment, once per program run, to determine which
 * system to use.  The experiment is performed at initialiasation,
 * before the first directory-referencing operation, and all operations
 * therefore proceed with knowledge of which system is being used.
 * If any of the necessary system calls aren't supported by the C library,
 * such that calls to them don't compile, then instead of experimenting
 * we statically use only the backup system.
 *
 * The functions here provide a syscall-like interface.  Errors are
 * signalled in errno.
 */

#if QHAVE_OPENAT && QHAVE_FSTATAT && QHAVE_LINKAT && QHAVE_UNLINKAT && \
	QHAVE_FDOPENDIR
# define QMAY_DIRREF_BY_FD 1
#else
# define QMAY_DIRREF_BY_FD 0
#endif

struct dirref_by_name {
	ino_t ino;
	dev_t dev;
	char name[1]; /* struct hack */
};

typedef union {
#if QMAY_DIRREF_BY_FD
	int fd;
#endif /* QMAY_DIRREF_BY_FD */
	struct dirref_by_name *byname;
} dirref_t;

#if QMAY_DIRREF_BY_FD
enum {
	DIRREF_EXPERIMENT,
	DIRREF_BY_FD,
	DIRREF_BY_NAME
};
static int dirref_strategy = DIRREF_EXPERIMENT;
#endif /* QMAY_DIRREF_BY_FD */

PERL_STATIC_INLINE void dirref_ensure_strategy(void)
{
#if QMAY_DIRREF_BY_FD
# if AT_FDCWD == -1
#  define QAT_BADFD (-2)
# else /* AT_FDCWD != -1 */
#  define QAT_BADFD (-1)
# endif /* AT_FDCWD != -1 */
	int res;
	struct stat st;
	if(unlikely(dirref_strategy != DIRREF_EXPERIMENT)) return;
	res = openat_cloexec(QAT_BADFD, "", O_RDONLY, 0);
	if(unlikely(res != -1)) {
		(void) close(res);
	} else if(unlikely(errno == ENOSYS)) {
		by_name:
		dirref_strategy = DIRREF_BY_NAME;
		return;
	}
	res = fstatat(QAT_BADFD, "", &st, 0);
	if(likely(res == -1) && unlikely(errno == ENOSYS)) goto by_name;
	res = linkat(QAT_BADFD, "", QAT_BADFD, "", 0);
	if(likely(res == -1) && unlikely(errno == ENOSYS)) goto by_name;
	res = unlinkat(QAT_BADFD, "", 0);
	if(likely(res == -1) && unlikely(errno == ENOSYS)) goto by_name;
	dirref_strategy = DIRREF_BY_FD;
#endif /* QMAY_DIRREF_BY_FD */
}

PERL_STATIC_INLINE bool dirref_referential(void)
{
#if QMAY_DIRREF_BY_FD
	return likely(dirref_strategy == DIRREF_BY_FD);
#else /* !QMAY_DIRREF_BY_FD */
	return 0;
#endif /* !QMAY_DIRREF_BY_FD */
}

PERL_STATIC_INLINE dirref_t dirref_null(void)
{
	dirref_t null_dirref;
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		null_dirref.fd = -1;
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		null_dirref.byname = NULL;
	}
	return null_dirref;
}

PERL_STATIC_INLINE bool dirref_is_null(dirref_t dirref)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		return dirref.fd == -1;
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		return !dirref.byname;
	}
}

static char *dirref_path_concat(char const *base, char const *rel)
{
	size_t blen = strlen(base), rlen = strlen(rel);
	size_t tlen = blen + rlen;
	char *full;
	if(unlikely(tlen < blen)) goto enomem;
	tlen += 2;
	if(unlikely(tlen < 2)) goto enomem;
	full = malloc(tlen);
	if(!likely(full)) {
		enomem:
		errno = ENOMEM;
		return NULL;
	}
	(void) memcpy(full, base, blen);
	if(unlikely(blen == 0) || likely(base[blen-1] != '/'))
		full[blen++] = '/';
	(void) memcpy(full + blen, rel, rlen+1);
	return full;
}

static dirref_t dirref_open(char const *origname, struct stat *st)
{
	dirref_t dirref;
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		dirref.fd = open_cloexec(origname, O_RDONLY, 0);
		if(likely(dirref.fd != -1) &&
				unlikely(fstat(dirref.fd, st) == -1)) {
			int er = errno;
			(void) close(dirref.fd);
			errno = er;
			dirref.fd = -1;
		}
		return dirref;
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		char *fullname;
		size_t fullname_len, byname_len;
		bool free_fullname;
		if(unlikely(stat(origname, st) == -1)) goto error;
#if QHAVE_REALPATH
		long pmax;
# if QHAVE_PATHCONF && defined(_PC_PATH_MAX)
		pmax = pathconf(".", _PC_PATH_MAX);
		if(unlikely(pmax == -1))
# endif /* QHAVE_PATHCONF && _PC_PATH_MAX */
		{
# ifdef PATH_MAX
			pmax = PATH_MAX;
# else /* !PATH_MAX */
			pmax = 4096;
# endif /* !PATH_MAX */
		}
		if(unlikely((long)(size_t)pmax != pmax ||
				((size_t)pmax)+1 == 0))
			goto enomem;
		fullname = malloc(((size_t)pmax) + 1);
		if(!likely(fullname)) goto enomem;
		if(!likely(realpath(origname, fullname))) {
			int er = errno;
			free(fullname);
			errno = er;
			goto error;
		}
		free_fullname = 1;
#elif QHAVE_GETCWD
		size_t origname_len = strlen(origname);
		if(likely(origname[0] == '/')) {
			fullname = (char*)origname;
			fullname_len = origname_len;
			free_fullname = 0;
		} else {
			size_t bufsz = 256;
			char *cwd;
			cwd = malloc(bufsz);
			if(!likely(cwd)) goto enomem;
			while(1) {
				char *newbuf;
				if(likely(getcwd(cwd, bufsz))) break;
				if(unlikely(errno != ERANGE)) {
					int er = errno;
					free(cwd);
					errno = er;
					goto error;
				}
				bufsz <<= 2;
				if(!likely(bufsz)) goto enomem_free_cwd;
				newbuf = realloc(cwd, bufsz);
				if(!likely(newbuf)) {
					enomem_free_cwd:
					free(cwd);
					goto enomem;
				}
				cwd = newbuf;
			}
			fullname = dirref_path_concat(cwd, origname);
			free(cwd);
			if(!likely(fullname)) goto enomem;
			free_fullname = 1;
		}
#else /* !QHAVE_REALPATH && !QHAVE_GETCWD */
 #error neither realpath nor getcwd available
#endif /* !QHAVE_REALPATH && !QHAVE_GETCWD */
		fullname_len = strlen(fullname);
		byname_len = offsetof(struct dirref_by_name, name) + 1 +
				fullname_len;
		if(unlikely(byname_len < fullname_len)) {
			enomem_maybe_free_fullname:
			if(free_fullname) free(fullname);
			enomem:
			errno = ENOMEM;
			error:
			dirref.byname = NULL;
			return dirref;
		}
		dirref.byname = malloc(byname_len);
		if(!likely(dirref.byname)) goto enomem_maybe_free_fullname;
		dirref.byname->dev = st->st_dev;
		dirref.byname->ino = st->st_ino;
		(void) memcpy(dirref.byname->name, fullname, fullname_len+1);
		if(free_fullname) free(fullname);
		return dirref;
	}
}

PERL_STATIC_INLINE void dirref_close(dirref_t dirref)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		(void) close(dirref.fd);
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		free(dirref.byname);
	}
}

static bool dirref_byname_ok(struct dirref_by_name *byname)
{
	struct stat st;
	if(unlikely(stat(byname->name, &st) == -1)) {
		if(likely(errno == ENOENT) || likely(errno == ENOTDIR))
			errno = EIO;
		return 0;
	} else if(likely(st.st_dev == byname->dev &&
			st.st_ino == byname->ino)) {
		return 1;
	} else {
		errno = EIO;
		return 0;
	}
}

PERL_STATIC_INLINE DIR *dirref_at_opendir(dirref_t dirref)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		DIR *dirh;
		int fd = openat_cloexec(dirref.fd, ".", O_RDONLY, 0);
		if(unlikely(fd == -1)) return NULL;
		dirh = fdopendir(fd);
		if(!likely(dirh)) {
			int er = errno;
			(void) close(fd);
			errno = er;
		}
		return dirh;
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		if(!likely(dirref_byname_ok(dirref.byname))) return NULL;
		return opendir(dirref.byname->name);
	}
}

static int dirref_via_open_cloexec(dirref_t dirref, char const *rel,
	int flags, mode_t mode)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		return openat_cloexec(dirref.fd, rel, flags, mode);
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		char *path;
		int res, er;
		path = dirref_path_concat(dirref.byname->name, rel);
		if(!likely(path)) return -1;
		res = !likely(dirref_byname_ok(dirref.byname)) ? -1 :
			open_cloexec(path, flags, mode);
		er = errno;
		free(path);
		errno = er;
		return res;
	}
}

PERL_STATIC_INLINE int dirref_via_stat(dirref_t dirref, char const *rel,
	struct stat *st)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		return fstatat(dirref.fd, rel, st, 0);
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		char *path;
		int res, er;
		path = dirref_path_concat(dirref.byname->name, rel);
		if(!likely(path)) return -1;
		res = !likely(dirref_byname_ok(dirref.byname)) ? -1 :
			stat(path, st);
		er = errno;
		free(path);
		errno = er;
		return res;
	}
}

PERL_STATIC_INLINE int dirref_via_link(dirref_t dirref, char const *oldrel,
	char const *newrel)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		return linkat(dirref.fd, oldrel, dirref.fd, newrel, 0);
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		char *oldpath, *newpath;
		int res, er;
		oldpath = dirref_path_concat(dirref.byname->name, oldrel);
		if(!likely(oldpath)) return -1;
		newpath = dirref_path_concat(dirref.byname->name, newrel);
		if(!likely(newpath)) {
			free(oldpath);
			errno = ENOMEM;
			return -1;
		}
		res = !likely(dirref_byname_ok(dirref.byname)) ? -1 :
			link(oldpath, newpath);
		er = errno;
		free(oldpath);
		free(newpath);
		errno = er;
		return res;
	}
}

static int dirref_via_unlink(dirref_t dirref, char const *rel)
{
#if QMAY_DIRREF_BY_FD
	if(likely(dirref_strategy == DIRREF_BY_FD)) {
		return unlinkat(dirref.fd, rel, 0);
	} else
#endif /* QMAY_DIRREF_BY_FD */
	{
		char *path;
		int res, er;
		path = dirref_path_concat(dirref.byname->name, rel);
		if(!likely(path)) return -1;
		res = !likely(dirref_byname_ok(dirref.byname)) ? -1 :
			unlink(path);
		er = errno;
		free(path);
		errno = er;
		return res;
	}
}

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
PERL_STATIC_INLINE DIR **THX_closedirh_save(pTHX_ DIR *dirh)
{
	DIR **dirh_p;
	Newx(dirh_p, 1, DIR*);
	*dirh_p = dirh;
	SAVEDESTRUCTOR_X(THX_closedirh_cleanup, dirh_p);
	return dirh_p;
}

#define closedirh_early(dirhp) THX_closedirh_early(aTHX_ dirhp)
PERL_STATIC_INLINE void THX_closedirh_early(pTHX_ DIR **dirh_p)
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
	dirref_t dir;
	char filename[1]; /* struct hack */
};

static void THX_unlinkfile_cleanup(pTHX_ void *par_p_v)
{
	struct unlinkfile_cleanup_par *par_p = par_p_v;
	dirref_t dir = par_p->dir;
	if(!likely(dirref_is_null(dir)))
		(void) dirref_via_unlink(dir, par_p->filename);
	Safefree(par_p_v);
}

#define unlinkfile_save(dir, fn) THX_unlinkfile_save(aTHX_ dir, fn)
static struct unlinkfile_cleanup_par *THX_unlinkfile_save(pTHX_ dirref_t dir,
	char const *filename)
{
	struct unlinkfile_cleanup_par *par_p;
	char *par_p_c;
	size_t fnlen = strlen(filename) + 1;
	Newx(par_p_c, offsetof(struct unlinkfile_cleanup_par, filename) + fnlen,
		char);
	par_p = (struct unlinkfile_cleanup_par *)par_p_c;
	par_p->dir = dir;
	(void) memcpy(par_p->filename, filename, fnlen);
	SAVEDESTRUCTOR_X(THX_unlinkfile_cleanup, par_p);
	return par_p;
}

#define unlinkfile_cancel(par_p) THX_unlinkfile_cancel(aTHX_ par_p)
PERL_STATIC_INLINE void THX_unlinkfile_cancel(pTHX_
	struct unlinkfile_cleanup_par *par_p)
{
	par_p->dir = dirref_null();
}

#define unlinkfile_early(par_p) THX_unlinkfile_early(aTHX_ par_p)
static void THX_unlinkfile_early(pTHX_ struct unlinkfile_cleanup_par *par_p)
{
	dirref_t dir = par_p->dir;
	if(likely(!dirref_is_null(dir))) {
		par_p->dir = dirref_null();
		(void) dirref_via_unlink(dir, par_p->filename);
	}
}

typedef struct unlinkfile_cleanup_par *unlinkfile_ref_t;

/*
 * string unwrapping
 *
 * A struct pvl encapsulates an octet string held as octets in memory.
 * The memory's allocation is independent of this structure; the memory
 * must have sufficient lifetime for the use to which the pvl will be put.
 * pvl.pv may therefore point into an SV's buffer, or into separate
 * mortally-allocated memory, or into a file mapping.  The octet string
 * is not necessarily NUL-terminated; pvl.len must be used to determine
 * the length.
 *
 * A null value (representing the absence of a string) can be represented
 * as a pvl with pvl.pv null.
 *
 * pvl_from_arg() handles taking an octet string argument supplied
 * by a user of this module.  It processes get magic exactly once.
 * The pvl that it returns points either into the argument's buffer or
 * to mortally-allocated memory.
 */

struct pvl {
	char *pv;
	size_t len;
};

PERL_STATIC_INLINE struct pvl pvl_null(void)
{
	struct pvl pvl;
	pvl.pv = NULL;
	pvl.len = 0;
	return pvl;
}

PERL_STATIC_INLINE bool pvl_is_null(struct pvl pvl)
{
	return !pvl.pv;
}

#define pvl_from_arg(role, au, arg) THX_pvl_from_arg(aTHX_ role, au, arg)
static struct pvl THX_pvl_from_arg(pTHX_ char const *role, bool allow_undef,
	SV *arg)
{
	STRLEN len;
	size_t d;
	char *p, *q, *e;
	struct pvl pvl;
	SvGETMAGIC(arg);
	if(unlikely(sv_is_glob(arg) || sv_is_regexp(arg))) goto invalid;
	if(allow_undef && !SvOK(arg)) return pvl_null();
	if(!likely(SvFLAGS(arg) &
			(SVf_IOK|SVf_NOK|SVf_POK|SVp_IOK|SVp_NOK|SVp_POK))) {
		invalid:
		croak("%s is %s", role,
			allow_undef ? "neither an octet string nor undef" :
				"not an octet string");
	}
	pvl.pv = SvPV_nomg(arg, len);
	pvl.len = len;
	if(!unlikely(SvUTF8(arg))) return pvl;
	e = pvl.pv + pvl.len;
	for(d = 0, p = pvl.pv; p != e; ) {
		U8 c = (U8)*p++;
		if(unlikely(c & 0x80)) {
			if(unlikely(c < 0xc2 || c > 0xc3 || p == e))
				goto invalid;
			c = (U8)*p++;
			if(!likely(c >= 0x80 && c <= 0xbf)) goto invalid;
			d++;
		}
	}
	if(likely(d == 0)) return pvl;
	p = pvl.pv;
	pvl.len -= d;
	Newx(pvl.pv, pvl.len, char);
	SAVEFREEPV(pvl.pv);
	for(q = pvl.pv; p != e; q++) {
		U8 c = (U8)*p++;
		if(unlikely(c & 0x80))
			c = ((c & 0x03) << 6) | (((U8)*p++) & 0x3f);
		*q = (char)c;
	}
	return pvl;
}

/* byte definition */

#define BYTE_NBIT 8

typedef U8 byte;
#define BYTE_MAX 0xff

/* word definition */

#define WORD_SZ_LOG2 3
#define WORD_SZ (1<<WORD_SZ_LOG2)
#define WORD_ALIGN_BITS (WORD_SZ-1)
#define IS_WORD_ALIGNED(v) (!((v) & WORD_ALIGN_BITS))
#define WORD_ALIGN(v) (((v) + WORD_ALIGN_BITS) & ~WORD_ALIGN_BITS)

#define WORD_NBIT (BYTE_NBIT << WORD_SZ_LOG2)

typedef U64 word;
#define WORD_C UINT64_C
enum { ASSERT_WORD_SIZE = 1/(!!(sizeof(word) == (1<<WORD_SZ_LOG2))) };
#define WORD_MAX WORD_C(0xffffffffffffffff)

/*
 * fanout limit
 *
 * This parameter is currently fixed at compile time.  The value 15 is the
 * result of an experiment with an amd64 system.  (Perhaps it is a sweet
 * spot due to node buffers coming in just under a power of two size.)
 *
 * FUTURE: should experiment with MAXSPLAY on more systems, to come up
 * with a formula that optimises it more widely.
 *
 * FUTURE: this parameter could be treated as a variable, to make it
 * possible to read files written by systems using other values.
 */

#define MAXSPLAY 15

/*
 * parameter word
 *
 * Variable aspects of the file format are encapsulated in a word quantity
 * that is included in file headers.  Some of the parameters are currently
 * fixed at compile time, and others are runtime variable.
 *
 * FUTURE: if there is any change in the file formats, it should be
 * indicated by setting flags or changing a version number in the
 * parameter word.  ext2's concept of readonly-compatible changes may
 * be useful.
 */

#if MAXSPLAY < 3 || MAXSPLAY >= BYTE_MAX || !(MAXSPLAY & 1)
 #error bad parameter: splay limit unacceptable
#endif /* MAXSPLAY < 3 || MAXSPLAY >= BYTE_MAX || !(MAXSPLAY & 1) */

#define PARAMETER_WORD_FIXED_PART_VALUE (MAXSPLAY<<16)

#define PARAMETER_WORD(lsl, psl) \
	(((word)(lsl)) | (((word)psl)<<8) | PARAMETER_WORD_FIXED_PART_VALUE)

#define PARAMETER_WORD_LINE_SZ_LOG2(par) ((int)((par) & 0xff))
#define PARAMETER_WORD_PAGE_SZ_LOG2(par) ((int)(((par) >> 8) & 0xff))
#define PARAMETER_WORD_FIXED_PART(par) ((par) & ~(word)0xffff)

PERL_STATIC_INLINE int llog2(long v)
{
	int g;
	if(v <= 0) return -1;
	for(g = 0; !(v & 1); g++) v >>= 1;
	return v == 1 ? g : -1;
}

PERL_STATIC_INLINE int parameter_known_line_size_log2(void)
{
#if QHAVE_SYSCONF
	int h = -1, l;
# ifdef _SC_LEVEL1_DCACHE_LINESIZE
	l = llog2(sysconf(_SC_LEVEL1_DCACHE_LINESIZE));
	if(l > h) h = l;
# endif /* _SC_LEVEL1_DCACHE_LINESIZE */
# ifdef _SC_LEVEL2_CACHE_LINESIZE
	l = llog2(sysconf(_SC_LEVEL2_CACHE_LINESIZE));
	if(l > h) h = l;
# endif /* _SC_LEVEL2_DCACHE_LINESIZE */
# ifdef _SC_LEVEL3_CACHE_LINESIZE
	l = llog2(sysconf(_SC_LEVEL3_CACHE_LINESIZE));
	if(l > h) h = l;
# endif /* _SC_LEVEL3_DCACHE_LINESIZE */
# ifdef _SC_LEVEL4_CACHE_LINESIZE
	l = llog2(sysconf(_SC_LEVEL4_CACHE_LINESIZE));
	if(l > h) h = l;
# endif /* _SC_LEVEL4_DCACHE_LINESIZE */
	return h;
#else /* !QHAVE_SYSCONF */
	return -1;
#endif /* !QHAVE_SYSCONF */
}

PERL_STATIC_INLINE int parameter_known_page_size_log2(void)
{
	int l;
	PERL_UNUSED_VAR(l);
#if QHAVE_SYSCONF
# ifdef _SC_PAGESIZE
	l = llog2(sysconf(_SC_PAGESIZE));
	if(l != -1) return l;
# endif /* _SC_PAGESIZE */
# ifdef _SC_PAGE_SIZE
#  ifdef _SC_PAGESIZE
	if(_SC_PAGE_SIZE != _SC_PAGESIZE)
#  endif /* _SC_PAGESIZE */
	{
		l = llog2(sysconf(_SC_PAGE_SIZE));
		if(l != -1) return l;
	}
# endif /* _SC_PAGE_SIZE */
#endif /* QHAVE_SYSCONF */
#if QHAVE_GETPAGESIZE
	l = llog2(getpagesize());
	if(l != -1) return l;
#endif /* QHAVE_GETPAGESIZE */
	return -1;
}

PERL_STATIC_INLINE word parameter_preferred(void)
{
	int lsl = parameter_known_line_size_log2();
	int psl = parameter_known_page_size_log2();
	/*
	 * Where line/page sizes are not definitively known, guess.
	 * The standard guesses are line size 2^6 bytes and page size
	 * 2^12 bytes, matching the ia32/amd64 processors that are common
	 * in 2013.  If one size is known and the other is not, the guess
	 * for the unknown parameter will be modified if necessary such
	 * that the guessed page size is no smaller than the guessed
	 * line size.  Known line and page sizes could nevertheless be
	 * the other way round.
	 */
	if(psl == -1) psl = lsl > 12 ? lsl : 12;
	if(lsl == -1) lsl = psl < 6 ? psl : 6;
	/*
	 * Having determined (our best guess of) the system's actual
	 * line and page size, these must now be modified to conform to
	 * the requirements of the shash format.  The shash line size
	 * must be at least word size, and the shash page size must be
	 * at least the line size.  Sizes that are too big to deal with,
	 * such that intra-page pointers wouldn't fit into a word, will
	 * be reduced to a size that's still too bit to deal with but
	 * at least is sure not to overflow the fields they have to fit.
	 */
	if(lsl < WORD_SZ_LOG2) lsl = WORD_SZ_LOG2;
	if(psl < lsl) psl = lsl;
	if(psl > WORD_NBIT) psl = WORD_NBIT;
	if(lsl > WORD_NBIT) lsl = WORD_NBIT;
	return PARAMETER_WORD(lsl, psl);
}

/*
 * size parameters
 *
 * A notional line and page size must be chosen for each shash, and should
 * preferably (for performance) match the target machine architecture.
 * Variable aspects of file layout depend on the chosen line and page
 * size.  File offsets are precomputed and stored in struct sizes.
 *
 * In the data file header, the zero padding after the initial immutable
 * words (filling the remainder of the first line, unless lines are
 * very small) is picked out as a feature of the header so that it can
 * be used to represent the empty btree node and the empty string.
 */

#define DHD_MAGIC 0
#define DHD_PARAM (DHD_MAGIC+WORD_SZ)
#define DHD_LENGTH (DHD_PARAM+WORD_SZ)
#define DHD_ZEROPAD (DHD_LENGTH+WORD_SZ)

#define MFL_MAGIC 0
#define MFL_PARAM (MFL_MAGIC+WORD_SZ)

struct sizes {
	word line_align_bits, page_align_bits;
	word dhd_nextalloc_space, dhd_current_root, dhd_sz;
	word dhd_zeropad_sz;
	word mfl_lastalloc_datafileid, mfl_current_datafileid, mfl_sz;
};

#define IS_LINE_ALIGNED(sizes, v) (!((v) & (sizes)->line_align_bits))
#define LINE_ALIGN(sizes, v) ((((v)-1) | (sizes)->line_align_bits) + 1)
#define IS_PAGE_ALIGNED(sizes, v) (!((v) & (sizes)->page_align_bits))
#define PAGE_ALIGN(sizes, v) ((((v)-1) | (sizes)->page_align_bits) + 1)

#define sizes_construct(lsl, psl) THX_sizes_construct(aTHX_ lsl, psl)
PERL_STATIC_INLINE struct sizes const *THX_sizes_construct(pTHX_
	int line_sz_log2, int page_sz_log2)
{
	struct sizes *sizes;
	Newx(sizes, 1, struct sizes);
	if(line_sz_log2 < WORD_SZ_LOG2 || page_sz_log2 < line_sz_log2 ||
			line_sz_log2 >= WORD_NBIT ||
			page_sz_log2 >= WORD_NBIT) {
		bad_parameters:
		Safefree(sizes);
		return NULL;
	}
	sizes->line_align_bits = (((word)1) << line_sz_log2) - 1;
	sizes->page_align_bits = (((word)1) << page_sz_log2) - 1;
	sizes->dhd_nextalloc_space = LINE_ALIGN(sizes, DHD_ZEROPAD);
	if(!sizes->dhd_nextalloc_space) goto bad_parameters;
	sizes->dhd_current_root =
		LINE_ALIGN(sizes, sizes->dhd_nextalloc_space + WORD_SZ);
	if(!sizes->dhd_current_root) goto bad_parameters;
	sizes->dhd_sz = LINE_ALIGN(sizes, sizes->dhd_current_root + WORD_SZ);
	if(!sizes->dhd_sz) goto bad_parameters;
	sizes->dhd_zeropad_sz = sizes->dhd_nextalloc_space - DHD_ZEROPAD;
	sizes->mfl_lastalloc_datafileid =
		LINE_ALIGN(sizes, MFL_PARAM + WORD_SZ);
	if(!sizes->mfl_lastalloc_datafileid) goto bad_parameters;
	sizes->mfl_current_datafileid =
		LINE_ALIGN(sizes, sizes->mfl_lastalloc_datafileid + WORD_SZ);
	if(!sizes->mfl_current_datafileid) goto bad_parameters;
	sizes->mfl_sz =
		PAGE_ALIGN(sizes, sizes->mfl_current_datafileid + WORD_SZ);
	if(!sizes->mfl_sz) goto bad_parameters;
	return sizes;
}

static PTR_TBL_t *sizes_table;

#define sizes_lookup(par) THX_sizes_lookup(aTHX_ par)
static struct sizes const *THX_sizes_lookup(pTHX_ word par)
{
	int line_sz_log2 = PARAMETER_WORD_LINE_SZ_LOG2(par);
	int page_sz_log2 = PARAMETER_WORD_PAGE_SZ_LOG2(par);
	void *key = NUM2PTR(void*, line_sz_log2 | (page_sz_log2 << 8));
	void *sizes_v = ptr_table_fetch(sizes_table, key);
	if(sizes_v) {
		return sizes_v;
	} else {
		struct sizes const *sizes =
			sizes_construct(line_sz_log2, page_sz_log2);
		if(!sizes) return NULL;
		ptr_table_store(sizes_table, key, (void*)sizes);
		return sizes;
	}
}

/*
 * magic numbers
 */

#define DATA_FILE_MAGIC WORD_C(0xc693dac5ed5e47c2)
#define MASTER_FILE_MAGIC WORD_C(0xa58afd185cbf5af7)

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

PERL_STATIC_INLINE word sync_read_word(word const *ptr)
{
	return *(word const volatile *)ptr;
}

/* refcounted handling of mmaps */

#define mmap_addr_from_sv(mapsv) THX_mmap_addr_from_sv(aTHX_ mapsv)
PERL_STATIC_INLINE void *THX_mmap_addr_from_sv(pTHX_ SV *mapsv)
{
	return (void *)SvPVX(mapsv);
}

#define mmap_len_from_sv(mapsv) THX_mmap_len_from_sv(aTHX_ mapsv)
PERL_STATIC_INLINE size_t THX_mmap_len_from_sv(pTHX_ SV *mapsv)
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
#if PERL_VERSION_GE(5,7,3)
	NULL, /* copy */
	NULL, /* dup */
#endif /* >=5.7.3 */
#if (PERL_VERSION_GE(5,8,9) && !PERL_VERSION_GE(5,9,0)) || \
		PERL_VERSION_GE(5,9,3)
	NULL, /* local */
#endif /* (>=5.8.9 && <5.9.0) || >=5.9.3 */
};

#define mmap_early_unmap(mapsv) THX_mmap_early_unmap(aTHX_ mapsv)
PERL_STATIC_INLINE void THX_mmap_early_unmap(pTHX_ SV *mapsv)
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
	(void) sv_magicext(mapsv, NULL, PERL_MAGIC_ext, (MGVTBL*)&mmap_mgvtbl,
				NULL, 0);
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
	struct sizes const *sizes;
	SV *top_pathname_sv;
	SV *data_mmap_sv;
	void *data_mmap;
	unsigned mode;
	word data_size;
	word parameter;
	union {
		struct {
			word data_file_id;
			dirref_t dir;
			SV *master_mmap_sv;
			void *master_mmap;
		} live;
		struct {
			word root;
		} snapshot;
	} u;
};

static HV *shash_handle_stash;

#define shash_or_null_from_svref(shsvref) \
	THX_shash_or_null_from_svref(aTHX_ shsvref)
static struct shash *THX_shash_or_null_from_svref(pTHX_ SV *shsvref)
{
	SV *shsv;
	SvGETMAGIC(shsvref);
	return likely(SvROK(shsvref) && (shsv = SvRV(shsvref)) &&
			SvOBJECT(shsv) && SvSTASH(shsv) == shash_handle_stash) ?
		(struct shash *)SvPVX(shsv) : NULL;
}

#define arg_error_notshash() THX_arg_error_notshash(aTHX)
PERL_STATIC_INLINE void THX_arg_error_notshash(pTHX) __attribute__noreturn__;
PERL_STATIC_INLINE void THX_arg_error_notshash(pTHX)
{
	croak("handle is not a shared hash handle");
}

#define shash_from_svref(shsvref) THX_shash_from_svref(aTHX_ shsvref)
static struct shash *THX_shash_from_svref(pTHX_ SV *shsvref)
{
	struct shash *sh = shash_or_null_from_svref(shsvref);
	if(!likely(sh)) arg_error_notshash();
	return sh;
}

#define arg_is_shash(arg) THX_arg_is_shash(aTHX_ arg)
PERL_STATIC_INLINE bool THX_arg_is_shash(pTHX_ SV *arg)
{
	return !!shash_or_null_from_svref(arg);
}

#define arg_check_shash(arg) THX_arg_check_shash(aTHX_ arg)
static void THX_arg_check_shash(pTHX_ SV *arg)
{
	if(!likely(arg_is_shash(arg))) arg_error_notshash();
}

#define shash_error(sh, act, msg) THX_shash_error(aTHX_ sh, act, msg)
static void THX_shash_error(pTHX_ struct shash *sh, char const *action,
	char const *message) __attribute__noreturn__;
static void THX_shash_error(pTHX_ struct shash *sh, char const *action,
	char const *message)
{
#if !PERL_VERSION_GE(5,8,1)
	SV *m = mess("can't %s shared hash %"SVf": %s", action,
			sh->top_pathname_sv, message);
	sv_setsv(ERRSV, m);
	croak(NULL);
#else /* >=5.8.1 */
# if !PERL_VERSION_GE(5,10,1)
	SvUTF8_off(ERRSV);
# endif /* <5.10.1 */
	croak("can't %s shared hash %"SVf": %s", action,
		sh->top_pathname_sv, message);
#endif /* >=5.8.1 */
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

#define shash_check_readable(sh, act) THX_shash_check_readable(aTHX_ sh, act)
static void THX_shash_check_readable(pTHX_ struct shash *sh, char const *action)
{
	if(!likely(sh->mode & STOREMODE_READ))
		shash_error(sh, action,
			"shared hash was opened in unreadable mode");
}

#define shash_check_writable(sh, act) THX_shash_check_writable(aTHX_ sh, act)
static void THX_shash_check_writable(pTHX_ struct shash *sh, char const *action)
{
	if(unlikely(sh->mode & STOREMODE_SNAPSHOT))
		shash_error(sh, action, "shared hash handle is a snapshot");
	if(!likely(sh->mode & STOREMODE_WRITE))
		shash_error(sh, action,
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
	(void) sprintf(buf, "%s%08x%08x",
		DATA_FILENAME_PREFIX, (unsigned)(fileid >> 32),
		(unsigned)(fileid & WORD_C(0xffffffff)));
}

#define TEMP_FILENAME_BUFSIZE (FILENAME_PREFIX_LEN+8+8+8+1)

#define dir_make_temp_filename(buf) THX_dir_make_temp_filename(aTHX_ buf)
PERL_STATIC_INLINE void THX_dir_make_temp_filename(pTHX_ char *buf)
{
	unsigned s, ns;
#if QHAVE_CLOCK_GETTIME && defined(CLOCK_REALTIME)
	{
		struct timespec ts;
		if(likely(clock_gettime(CLOCK_REALTIME, &ts) == 0)) {
			s = ts.tv_sec;
			ns = ts.tv_nsec;
			goto got_time;
		}
	}
#endif /* QHAVE_CLOCK_GETTIME && CLOCK_REALTIME */
#if QHAVE_GETTIMEOFDAY
	{
		struct timeval tv;
		if(likely(gettimeofday(&tv, NULL) == 0)) {
			s = tv.tv_sec;
			ns = tv.tv_usec * 1000;
			goto got_time;
		}
	}
#endif /* QHAVE_GETTIMEOFDAY */
	{
		s = time(NULL);
		ns = 0;
		goto got_time;
	}
	got_time:
	(void) sprintf(buf, "%s%08x%08x%08x", TEMP_FILENAME_PREFIX,
		s & 0xffffffffU, ns & 0xffffffffU,
		((unsigned)getpid()) & 0xffffffffU);
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


typedef void (*iterate_fn_t)(pTHX_ struct shash *sh, char const *fn, word arg);

#define dir_iterate(sh, act, iter, arg) \
	THX_dir_iterate(aTHX_ sh, act, iter, arg)
static void THX_dir_iterate(pTHX_ struct shash *sh, char const *action,
	iterate_fn_t THX_iterate, word arg)
{
	DIR *dirh;
	closedirh_ref_t dirhr;
	int old_errno = errno;
	dirh = dirref_at_opendir(sh->u.live.dir);
	if(!likely(dirh)) shash_error_errno(sh, action);
	dirhr = closedirh_save(dirh);
	while(1) {
		struct dirent *de;
		errno = 0;
		de = readdir(dirh);
		if(!likely(de)) break;
		THX_iterate(aTHX_ sh, de->d_name, arg);
	}
	if(unlikely(errno)) shash_error_errno(sh, action);
	errno = old_errno;
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
		(void) dirref_via_unlink(sh->u.live.dir, fn);
}

#define dir_clean(sh, act, curfileid) THX_dir_clean(aTHX_ sh, act, curfileid)
PERL_STATIC_INLINE void THX_dir_clean(pTHX_ struct shash *sh,
	char const *action, word curfileid)
{
	dir_iterate(sh, action, THX_dir_clean_file, curfileid);
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
 * Allocation is managed separately for each write operation.  The state
 * of allocation is managed in a struct shash_alloc, which must be created
 * (on the stack) by the top-level mutation function.  Principally this
 * structure records any partial line that is owned by this process
 * and available for allocation.  When a write operation is complete,
 * the allocation state (and any unused partial line) is discarded.
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
	tmps_ix_t old_tmps_floor;
	datafileid = sync_read_word(&WORD_AT(sh->u.live.master_mmap,
					sh->sizes->mfl_current_datafileid));
	if(likely(mapsv = sh->data_mmap_sv)) {
		if(likely(datafileid == sh->u.live.data_file_id)) return;
		sh->data_mmap_sv = NULL;
		SvREFCNT_dec_NN(mapsv);
	}
	attempt_to_open_data:
	if(unlikely(datafileid == 0)) {
		word dsz = PAGE_ALIGN(sh->sizes, sh->sizes->dhd_sz + WORD_SZ);
		char *map;
		if(!dsz || (word)(size_t)dsz != dsz || (word)(STRLEN)dsz != dsz)
			shash_error_errnum(sh, "use", ENOMEM);
		Newxz(map, dsz, char);
		WORD_AT(map, DHD_MAGIC) = DATA_FILE_MAGIC;
		WORD_AT(map, DHD_PARAM) = sh->parameter;
		WORD_AT(map, DHD_LENGTH) = dsz;
		WORD_AT(map, sh->sizes->dhd_nextalloc_space) = dsz;
		WORD_AT(map, sh->sizes->dhd_current_root) =
			sh->sizes->dhd_sz | PTR_FLAG_ROLLOVER;
		mapsv = newSV_type(SVt_PV);
		SvPV_set(mapsv, map);
		SvLEN_set(mapsv, dsz);
		sh->data_mmap = map;
		sh->data_mmap_sv = mapsv;
		sh->data_size = dsz;
		sh->u.live.data_file_id = 0;
		return;
	}
	dir_make_data_filename(data_filename, datafileid);
	data_fd = dirref_via_open_cloexec(sh->u.live.dir, data_filename,
			((sh->mode & STOREMODE_WRITE) ? O_RDWR : O_RDONLY), 0);
	if(unlikely(data_fd == -1)) {
		word newdatafileid;
		if(unlikely(errno != ENOENT)) shash_error_errno(sh, "use");
		newdatafileid = sync_read_word(&WORD_AT(sh->u.live.master_mmap,
					sh->sizes->mfl_current_datafileid));
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
			(off_t)(word)statbuf.st_size == statbuf.st_size &&
			(word)statbuf.st_size >= sh->sizes->dhd_sz &&
			IS_PAGE_ALIGNED(sh->sizes, (word)statbuf.st_size)))
		shash_error_data(sh);
	sh->data_size = statbuf.st_size;
	old_tmps_floor = PL_tmps_floor;
	SAVETMPS;
	mapsv = mmap_as_sv(data_fd, sh->data_size,
			!!(sh->mode & STOREMODE_WRITE));
	if(!likely(mapsv)) shash_error_errno(sh, "use");
	sh->u.live.data_file_id = datafileid;
	sh->data_mmap_sv = SvREFCNT_inc_simple_NN(mapsv);
	sh->data_mmap = mmap_addr_from_sv(mapsv);
	FREETMPS;
	PL_tmps_floor = old_tmps_floor;
	closefd_early(fdr);
	if(!likely(WORD_AT(sh->data_mmap, DHD_MAGIC) == DATA_FILE_MAGIC &&
			WORD_AT(sh->data_mmap, DHD_PARAM) == sh->parameter &&
			WORD_AT(sh->data_mmap, DHD_LENGTH) == sh->data_size))
		shash_error_data(sh);
}

#define shash_error_toobig(sh, act) THX_shash_error_toobig(aTHX_ sh, act)
static void THX_shash_error_toobig(pTHX_ struct shash *sh, char const *action)
	__attribute__noreturn__;
static void THX_shash_error_toobig(pTHX_ struct shash *sh, char const *action)
{
	shash_error(sh, action, "data too large for a shared hash");
}

struct shash_alloc {
	word prealloc_len;
	byte *prealloc_loc;
	char const *action;
	jmp_buf fulljb;
};

#define shash_alloc(sh, alloc, len, pp) \
	THX_shash_alloc(aTHX_ sh, alloc, len, pp)
static word *THX_shash_alloc(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	word len, word *ptr_p)
{
	byte *prealloc_end, *loc;
	word *nextalloc_p, data_size, pos, epos;
	word wlen = WORD_ALIGN(len), llen;
	if(!likely(wlen) && unlikely(len))
		shash_error_toobig(sh, alloc->action);
	if(unlikely(wlen <= alloc->prealloc_len)) goto got_prealloc;
	prealloc_end = alloc->prealloc_loc + alloc->prealloc_len;
	nextalloc_p = &WORD_AT(sh->data_mmap, sh->sizes->dhd_nextalloc_space);
	data_size = sh->data_size;
	pos = sync_read_word(nextalloc_p);
	if(unlikely(!IS_LINE_ALIGNED(sh->sizes, pos) || pos > data_size))
		shash_error_data(sh);
	if(likely(&BYTE_AT(sh->data_mmap, pos) == prealloc_end)) {
		llen = LINE_ALIGN(sh->sizes, wlen - alloc->prealloc_len);
		if(!likely(llen)) shash_error_toobig(sh, alloc->action);
		epos = pos + llen;
		if(unlikely(epos < pos || epos > data_size))
			longjmp(alloc->fulljb, 1);
		if(likely(__sync_bool_compare_and_swap(nextalloc_p,
				pos, epos))) {
			alloc->prealloc_len += llen;
			goto got_prealloc;
		}
	}
	llen = LINE_ALIGN(sh->sizes, wlen);
	if(!likely(llen)) shash_error_toobig(sh, alloc->action);
	while(1) {
		pos = sync_read_word(nextalloc_p);
		if(unlikely(!IS_LINE_ALIGNED(sh->sizes, pos) ||
				pos > data_size))
			shash_error_data(sh);
		epos = pos + llen;
		if(unlikely(epos < pos || epos > data_size))
			longjmp(alloc->fulljb, 1);
		if(likely(__sync_bool_compare_and_swap(nextalloc_p,
				pos, epos))) {
			byte *newalloc_loc = &BYTE_AT(sh->data_mmap, pos);
			alloc->prealloc_loc = newalloc_loc;
			alloc->prealloc_len = llen;
			break;
		}
	}
	got_prealloc:
	loc = alloc->prealloc_loc;
	alloc->prealloc_loc += wlen;
	alloc->prealloc_len -= wlen;
	*ptr_p = loc - (byte*)sh->data_mmap;
	return (word*)loc;
}

/* strings in the shash */

#define string_as_pvl(sh, ptr) THX_string_as_pvl(aTHX_ sh, ptr)
static struct pvl THX_string_as_pvl(pTHX_ struct shash *sh, word ptr)
{
	word len, *loc, spc, alloclen;
	struct pvl pvl;
	loc = pointer_loc(sh, ptr, &spc);
	len = loc[0];
	alloclen = len + WORD_SZ+1;
	if(unlikely(alloclen < WORD_SZ+1 || alloclen > spc))
		shash_error_data(sh);
	if(unlikely((word)(size_t)len != len))
		shash_error_errnum(sh, "use", ENOMEM);
	pvl.pv = (char*)&loc[1];
	pvl.len = len;
	if(unlikely(pvl.pv[pvl.len])) shash_error_data(sh);
	return pvl;
}

static MGVTBL const string_mmapref_mgvtbl;

#define string_as_sv(sh, act, ptr) THX_string_as_sv(aTHX_ sh, act, ptr)
static SV *THX_string_as_sv(pTHX_ struct shash *sh, char const *action,
	word ptr)
{
	struct pvl pvl = string_as_pvl(sh, ptr);
	SV *sv;
	if(unlikely((size_t)(STRLEN)pvl.len != pvl.len))
		shash_error_errnum(sh, action, ENOMEM);
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
	if(pvl.len < sizeof(XPVMG) *
			((sizeof(MAGIC)+sizeof(XPVMG)*2-1) / sizeof(XPVMG)) -
			sizeof(size_t)) {
		sv = newSVpvn_mortal(pvl.pv, pvl.len);
	} else {
		sv = sv_2mortal(newSV_type(SVt_PVMG));
		(void) sv_magicext(sv, sh->data_mmap_sv, PERL_MAGIC_ext,
				(MGVTBL*)&string_mmapref_mgvtbl, NULL, 0);
		SvPV_set(sv, pvl.pv);
		SvCUR_set(sv, pvl.len);
		SvPOK_on(sv);
	}
	SvREADONLY_on(sv);
	return sv;
}

#define string_cmp_pvl(sh, aptr, bpvl) THX_string_cmp_pvl(aTHX_ sh, aptr, bpvl)
static int THX_string_cmp_pvl(pTHX_ struct shash *sh, word aptr,
	struct pvl bpvl)
{
	struct pvl apvl = string_as_pvl(sh, aptr);
	int r = memcmp(apvl.pv, bpvl.pv,
			apvl.len < bpvl.len ? apvl.len : bpvl.len);
	return r ? r : apvl.len == bpvl.len ? 0 : apvl.len < bpvl.len ? -1 : 1;
}

#define string_eq_pvl(sh, aptr, bpvl) THX_string_eq_pvl(aTHX_ sh, aptr, bpvl)
PERL_STATIC_INLINE int THX_string_eq_pvl(pTHX_ struct shash *sh, word aptr,
	struct pvl bpvl)
{
	struct pvl apvl = string_as_pvl(sh, aptr);
	return apvl.len == bpvl.len && memcmp(apvl.pv, bpvl.pv, apvl.len) == 0;
}

#define string_write_from_pvl(sh, alloc, pvl) \
	THX_string_write_from_pvl(aTHX_ sh, alloc, pvl)
static word THX_string_write_from_pvl(pTHX_ struct shash *sh,
	struct shash_alloc *alloc, struct pvl pvl)
{
	word alloclen, ptr, *loc;
	if(unlikely((size_t)(word)pvl.len != pvl.len))
		shash_error_toobig(sh, alloc->action);
	if(unlikely(pvl.len == 0) &&
			likely(sh->sizes->dhd_zeropad_sz >= WORD_SZ+1))
		return ZEROPAD_PTR;
	alloclen = ((word)pvl.len) + WORD_SZ + 1;
	if(unlikely(alloclen < WORD_SZ+1))
		shash_error_toobig(sh, alloc->action);
	loc = shash_alloc(sh, alloc, alloclen, &ptr);
	loc[0] = pvl.len;
	(void) memcpy(&loc[1], pvl.pv, pvl.len);
	((byte*)&loc[1])[pvl.len] = 0;
	return ptr;
}

#define string_size(sh, ptr) THX_string_size(aTHX_ sh, ptr)
PERL_STATIC_INLINE word THX_string_size(pTHX_ struct shash *sh, word ptr)
{
	word spc;
	word len = pointer_loc(sh, ptr, &spc)[0];
	if(unlikely(len == 0) && likely(sh->sizes->dhd_zeropad_sz >= WORD_SZ+1))
		return 0;
	return WORD_ALIGN(len + WORD_SZ+1);
}

#define string_migrate(shf, ptrf, sht, alloct) \
	THX_string_migrate(aTHX_ shf, ptrf, sht, alloct)
PERL_STATIC_INLINE word THX_string_migrate(pTHX_ struct shash *shf, word ptrf,
	struct shash *sht, struct shash_alloc *alloct)
{
	return string_write_from_pvl(sht, alloct, string_as_pvl(shf, ptrf));
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

#define MINSPLAY ((MAXSPLAY+1)>>1)

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

#define bnode_search(sh, nl, sp, kpvl) THX_bnode_search(aTHX_ sh, nl, sp, kpvl)
static int THX_bnode_search(pTHX_ struct shash *sh, word const *loc,
	int splay, struct pvl keypvl)
{
	int l, r;
	word const *nodebody = bnode_body_loc(loc);
	for(l = 0, r = splay-1; l != r; ) {
		/* binary search invariant:
		 * search key > lower bount of subnode [l]
		 * search key < upper bound of subnode [r]
		 */
		int m = (l+r+1) >> 1;
		int cmpm = string_cmp_pvl(sh, nodebody[m << 1], keypvl);
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

#define bnode_write(sh, alloc, nh, ne, nb) \
	THX_bnode_write(aTHX_ sh, alloc, nh, ne, nb)
static word THX_bnode_write(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	int layer, int splay, word const *nodebody)
{
	word ptr, *loc;
	if(unlikely(splay == 0) && likely(layer == 0) &&
			likely(sh->sizes->dhd_zeropad_sz >= WORD_SZ))
		return ZEROPAD_PTR;
	loc = shash_alloc(sh, alloc, WORD_SZ + (splay << (WORD_SZ_LOG2+1)),
		&ptr);
	loc[0] = layer | (splay << 8);
	(void) memcpy(&loc[1], nodebody, splay << (WORD_SZ_LOG2+1));
	return ptr;
}

#define btree_get(sh, rt, keypvl) THX_btree_get(aTHX_ sh, rt, keypvl)
static word THX_btree_get(pTHX_ struct shash *sh, word root, struct pvl keypvl)
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
			cmp0 = string_cmp_pvl(sh, bnode_body_loc(ndloc)[0],
				keypvl);
			if(unlikely(cmp0 > 0)) return NULL_PTR;
			if(unlikely(cmp0 == 0)) goto exact_match;
		}
		pos = bnode_search(sh, ndloc, nsplay, keypvl);
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

#define btree_set(sh, alloc, rt, keypvl, valpvl) \
	THX_btree_set(aTHX_ sh, alloc, rt, keypvl, valpvl)
static word THX_btree_set(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	word oldroot, struct pvl keypvl, struct pvl valpvl)
{
	word const *nodeloc[LAYER_MAX+1];
	byte nodesplay[LAYER_MAX+1];
	byte index[LAYER_MAX+1];
	int layer = -1, root_layer = -1;
	word keyptr, valptr, ndptr = oldroot;
	word const *ndloc;
	int ntorm, ntoin;
	word inakey = 0, inaval = 0, inbkey = 0, inbval = 0;
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
			cmp0 = string_cmp_pvl(sh, bnode_body_loc(ndloc)[0],
				keypvl);
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
		pos = bnode_search(sh, ndloc, nsplay, keypvl);
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
	if(pvl_is_null(valpvl)) {
		/* delete */
		ntorm = 1;
		ntoin = 0;
		goto modify;
	} else {
		/* modify */
		if(string_eq_pvl(sh, valptr, valpvl)) return oldroot;
		ntorm = 1;
		ntoin = 1;
		inakey = keyptr;
		inaval = string_write_from_pvl(sh, alloc, valpvl);
		goto modify;
	}
	inexact_match:
	if(pvl_is_null(valpvl)) {
		/* no-op delete */
		return oldroot;
	} else {
		/* insert */
		index[0]++;
		ntorm = 0;
		ntoin = 1;
		inakey = string_write_from_pvl(sh, alloc, keypvl);
		inaval = string_write_from_pvl(sh, alloc, valpvl);
		goto modify;
	}
	modify:
	do {
		int nsplay = nodesplay[layer], modpos = index[layer];
		ndloc = nodeloc[layer];
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
				return bnode_write(sh, alloc, layer, nsplay,
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
			inaval = bnode_write(sh, alloc, layer, splitpos,
					nodebody);
			inbkey = nodebody[splitpos << 1];
			inbval = bnode_write(sh, alloc, layer, nsplay-splitpos,
					nodebody + (splitpos<<1));
			ntoin = 2;
		} else {
			inakey = nodebody[0];
			inaval = bnode_write(sh, alloc, layer, nsplay,
					nodebody);
			ntoin = 1;
		}
	} while(layer++ != root_layer);
	if(likely(ntoin == 1)) return inaval;
	if(unlikely(layer == LAYER_MAX+1))
		shash_error_toobig(sh, alloc->action);
	nodebody[0] = inakey;
	nodebody[1] = inaval;
	nodebody[2] = inbkey;
	nodebody[3] = inbval;
	return bnode_write(sh, alloc, layer, 2, nodebody);
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
			likely(sh->sizes->dhd_zeropad_sz >= WORD_SZ))
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
PERL_STATIC_INLINE word THX_btree_size(pTHX_ struct shash *sh, word root)
{
	word sz = btree_size_at_layer(sh, root, -1);
	if(!likely(sz)) return 0;
	sz = LINE_ALIGN(sh->sizes, sz);
	return sz ? sz : ~(word)0;
}

#define btree_migrate_at_layer(shf, ptrf, el, sht, alloct) \
	THX_btree_migrate_at_layer(aTHX_ shf, ptrf, el, sht, alloct)
static word THX_btree_migrate_at_layer(pTHX_ struct shash *shf, word ptrf,
	int expect_layer, struct shash *sht, struct shash_alloc *alloct)
{
	int layer, splay, i;
	word nodebody[MAXSPLAY*2];
	word const *locf = bnode_body_loc(bnode_check(shf, ptrf, expect_layer,
							&layer, &splay));
	word *loct = nodebody;
	if(likely(layer == 0)) {
		for(i = splay << 1; i--; ) {
			*loct++ = string_migrate(shf, *locf++, sht, alloct);
		}
	} else {
		for(i = splay; i--; ) {
			word spc;
			word ptrt = btree_migrate_at_layer(shf, locf[1],
					layer-1, sht, alloct);
			locf += 2;
			*loct++ =
				bnode_body_loc(pointer_loc(sht, ptrt, &spc))[0];
			*loct++ = ptrt;
		}
	}
	return bnode_write(sht, alloct, layer, splay, nodebody);
}

#define btree_migrate(shf, ptrf, sht, act) \
	THX_btree_migrate(aTHX_ shf, ptrf, sht, act)
static word THX_btree_migrate(pTHX_ struct shash *shf, word ptrf,
	struct shash *sht, char const *action)
{
	struct shash_alloc new_alloc;
	if(unlikely(setjmp(new_alloc.fulljb)))
		shash_error_errnum(sht, action, ENOSPC);
	new_alloc.action = action;
	new_alloc.prealloc_len = 0;
	return btree_migrate_at_layer(shf, ptrf, -1, sht, &new_alloc);
}

/* mechanism for reading from shash */

#define shash_root_for_read(sh) THX_shash_root_for_read(aTHX_ sh)
PERL_STATIC_INLINE word THX_shash_root_for_read(pTHX_ struct shash *sh)
{
	if(sh->mode & STOREMODE_SNAPSHOT) {
		return sh->u.snapshot.root;
	} else {
		shash_ensure_data_file(sh);
		return sync_read_word(&WORD_AT(sh->data_mmap,
					sh->sizes->dhd_current_root)) &
			~PTR_FLAG_ROLLOVER;
	}
}

/* mechanism for writing to shash */

#define shash_initiate_rollover(sh) THX_shash_initiate_rollover(aTHX_ sh)
PERL_STATIC_INLINE void THX_shash_initiate_rollover(pTHX_ struct shash *sh)
{
	word *root_p = &WORD_AT(sh->data_mmap, sh->sizes->dhd_current_root);
	while(1) {
		word root = sync_read_word(root_p);
		if(unlikely(root & PTR_FLAG_ROLLOVER)) break;
		if(likely(__sync_bool_compare_and_swap(root_p,
				root, root | PTR_FLAG_ROLLOVER)))
			break;
	}
}

#define shash_try_rollover(sh, act, addsz) \
	THX_shash_try_rollover(aTHX_ sh, act, addsz)
PERL_STATIC_INLINE word THX_shash_try_rollover(pTHX_ struct shash *sh,
	char const *action, word addsz)
{
	char filename[DATA_FILENAME_BUFSIZE];
	word *allocfileid_p;
	word old_file_id, old_root_word, old_root;
	word new_file_id, new_root, new_sz;
	struct stat statbuf;
	int new_fd;
	unlinkfile_ref_t new_ulr;
	closefd_ref_t new_fdr;
	struct shash new_sh;
	SV *old_mmap_sv;
	tmps_ix_t old_tmps_floor;
	old_root_word = sync_read_word(&WORD_AT(sh->data_mmap,
						sh->sizes->dhd_current_root));
	old_root = old_root_word & ~PTR_FLAG_ROLLOVER;
	new_sz = sh->sizes->dhd_sz + btree_size(sh, old_root);
	if(unlikely(new_sz < sh->sizes->dhd_sz || (new_sz & (((word)7) << 61))))
		shash_error_toobig(sh, action);
	new_sz <<= 3;
	new_sz += addsz;
	if(unlikely(new_sz < addsz)) shash_error_toobig(sh, action);
	new_sz = PAGE_ALIGN(sh->sizes, new_sz);
	if(unlikely(!new_sz)) shash_error_toobig(sh, action);
	if(unlikely((off_t)new_sz < 0 || (word)(off_t)new_sz != new_sz))
		shash_error_errnum(sh, action, EFBIG);
	new_sh.sizes = sh->sizes;
	new_sh.parameter = sh->parameter;
	new_sh.top_pathname_sv = sh->top_pathname_sv;
	allocfileid_p = &WORD_AT(sh->u.live.master_mmap,
					sh->sizes->mfl_lastalloc_datafileid);
	do {
		old_file_id = sync_read_word(allocfileid_p);
		new_file_id = old_file_id + 1;
		if(unlikely(new_file_id == 0)) new_file_id = 1;
	} while(!likely(__sync_bool_compare_and_swap(allocfileid_p,
				old_file_id, new_file_id)));
	if(unlikely(dirref_via_stat(sh->u.live.dir, MASTER_FILENAME, &statbuf)
			== -1))
		shash_error_errno(sh, action);
	dir_make_data_filename(filename, new_file_id);
	new_fd = dirref_via_open_cloexec(sh->u.live.dir, filename,
			O_RDWR|O_CREAT|O_EXCL, 0);
	if(unlikely(new_fd == -1)) shash_error_errno(sh, action);
	new_ulr = unlinkfile_save(sh->u.live.dir, filename);
	if(unlikely(fchown(new_fd, -1, statbuf.st_gid) == -1) &&
			unlikely(errno != EPERM))
		shash_error_errno(sh, action);
	if(unlikely(fchmod(new_fd, statbuf.st_mode &
			(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH))
			== -1))
		shash_error_errno(sh, action);
	if(unlikely(fchown(new_fd, statbuf.st_uid, -1) == -1) &&
			unlikely(errno != EPERM))
		shash_error_errno(sh, action);
	new_fdr = closefd_save(new_fd);
	if(unlikely(ftruncate(new_fd, new_sz) == -1)) {
		/*
		 * A file-too-big error may be reported as either
		 * EFBIG or EINVAL depending on OS.  The former is more
		 * enlightening to the user, so always report it that way.
		 */
		int e = errno;
		shash_error_errnum(sh, action, e == EINVAL ? EFBIG : e);
	}
	old_tmps_floor = PL_tmps_floor;
	SAVETMPS;
	new_sh.data_mmap_sv = mmap_as_sv(new_fd, new_sz, 1);
	if(!new_sh.data_mmap_sv) shash_error_errno(sh, action);
	new_sh.data_mmap = mmap_addr_from_sv(new_sh.data_mmap_sv);
	new_sh.data_size = new_sz;
	closefd_early(new_fdr);
	WORD_AT(new_sh.data_mmap, DHD_MAGIC) = DATA_FILE_MAGIC;
	WORD_AT(new_sh.data_mmap, DHD_PARAM) = sh->parameter;
	WORD_AT(new_sh.data_mmap, DHD_LENGTH) = new_sz;
	WORD_AT(new_sh.data_mmap, sh->sizes->dhd_nextalloc_space) =
		sh->sizes->dhd_sz;
	WORD_AT(new_sh.data_mmap, sh->sizes->dhd_current_root) = new_root =
		btree_migrate(sh, old_root, &new_sh, action);
	old_file_id = sh->u.live.data_file_id;
	if((!(old_root_word & PTR_FLAG_ROLLOVER) &&
			!likely(__sync_bool_compare_and_swap(
				&WORD_AT(sh->data_mmap,
					sh->sizes->dhd_current_root),
				old_root_word,
				old_root_word | PTR_FLAG_ROLLOVER))) ||
			!likely(__sync_bool_compare_and_swap(
				&WORD_AT(sh->u.live.master_mmap,
					sh->sizes->mfl_current_datafileid),
				old_file_id, new_file_id))) {
		unlinkfile_early(new_ulr);
		FREETMPS;
		PL_tmps_floor = old_tmps_floor;
		return NULL_PTR;
	}
	unlinkfile_cancel(new_ulr);
	old_mmap_sv = sh->data_mmap_sv;
	sh->data_mmap_sv = NULL;
	SvREFCNT_dec_NN(old_mmap_sv);
	sh->data_mmap_sv = SvREFCNT_inc_simple_NN(new_sh.data_mmap_sv);
	sh->data_mmap = new_sh.data_mmap;
	sh->data_size = new_sh.data_size;
	sh->u.live.data_file_id = new_file_id;
	FREETMPS;
	PL_tmps_floor = old_tmps_floor;
	if(old_file_id != 0) {
		dir_make_data_filename(filename, old_file_id);
		(void) dirref_via_unlink(sh->u.live.dir, filename);
	}
	return new_root;
}

typedef word (*mutate_fn_t)(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	word oldroot, void *mutate_arg);

#define shash_mutate(sh, act, mut, marg) \
	THX_shash_mutate(aTHX_ sh, act, mut, marg)
static void THX_shash_mutate(pTHX_ struct shash *sh, char const *action,
	mutate_fn_t THX_mutate, void *mutate_arg)
{
	struct shash_alloc alloc;
	volatile word addsz = PAGE_ALIGN(sh->sizes, 1<<20);
	volatile bool just_rolled_over = 0;
	alloc.action = action;
	if(unlikely(setjmp(alloc.fulljb))) {
		if(unlikely(just_rolled_over)) {
			word newaddsz = addsz <<= 1;
			if(!likely(newaddsz)) shash_error_toobig(sh, action);
		}
		shash_initiate_rollover(sh);
	}
	while(1) {
		word old_root, new_root;
		just_rolled_over = 0;
		shash_ensure_data_file(sh);
		old_root = sync_read_word(&WORD_AT(sh->data_mmap,
						sh->sizes->dhd_current_root));
		if(unlikely(old_root & PTR_FLAG_ROLLOVER)) {
			old_root = shash_try_rollover(sh, action, addsz);
			if(unlikely(old_root == NULL_PTR)) continue;
			dir_clean(sh, action, sh->u.live.data_file_id);
			just_rolled_over = 1;
		}
		alloc.prealloc_len = 0;
		new_root = THX_mutate(aTHX_ sh, &alloc, old_root, mutate_arg);
		if(likely(new_root == old_root) ||
				likely(__sync_bool_compare_and_swap(
					&WORD_AT(sh->data_mmap,
						sh->sizes->dhd_current_root),
					old_root, new_root)))
			break;
	}
}

/* shash opening and creation */

#define mode_from_sv(sv) THX_mode_from_sv(aTHX_ sv)
PERL_STATIC_INLINE unsigned THX_mode_from_sv(pTHX_ SV *modesv)
{
	char const *modepv, *modeend, *p;
	STRLEN modelen;
	unsigned mode = 0;
	SvGETMAGIC(modesv);
	if(!likely(sv_is_string(modesv))) croak("mode is not a string");
	modepv = SvPV_nomg(modesv, modelen);
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
PERL_STATIC_INLINE SV *THX_mode_as_sv(pTHX_ unsigned mode)
{
	char buf[4], *p;
	SV *modesv;
	p = buf;
	if(likely(mode & STOREMODE_READ)) *p++ = 'r';
	if(likely(mode & STOREMODE_WRITE)) *p++ = 'w';
	if(unlikely(mode & STOREMODE_CREATE)) *p++ = 'c';
	if(unlikely(mode & STOREMODE_EXCLUDE)) *p++ = 'e';
	modesv = newSVpvn_mortal(buf, p - buf);
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
	word id;
	PERL_UNUSED_ARG(arg);
	if(unlikely(dir_filename_class(fn, &id) == FILENAME_CLASS_BOGUS))
		shash_open_error_magic(sh);
}

#define shash_open(psv, msv) THX_shash_open(aTHX_ psv, msv)
static SV *THX_shash_open(pTHX_ SV *top_pathname_sv, SV *mode_sv)
{
	char const *top_pathname_pv;
	unsigned mode;
	struct shash *sh;
	SV *shsv, *shsvref, *mapsv;
	dirref_t dir;
	int master_fd;
	struct stat statbuf;
	unlinkfile_ref_t ulr;
	char temp_filename[TEMP_FILENAME_BUFSIZE];
	closefd_ref_t fdr;
	void *map;
	shsv = newSV_type(SVt_PVMG);
	shsvref = sv_2mortal(newRV_noinc(shsv));
	Newxz(sh, 1, struct shash);
	sh->u.live.dir = dirref_null();
	SvPV_set(shsv, (char *)sh);
	SvLEN_set(shsv, sizeof(struct shash));
	(void) sv_bless(shsvref, shash_handle_stash);
	SvGETMAGIC(top_pathname_sv);
	if(!likely(sv_is_string(top_pathname_sv)))
		croak("filename is not a string");
	{
		STRLEN len;
		char *pv = SvPV_nomg(top_pathname_sv, len);
		sh->top_pathname_sv = newSVpvn(pv, len);
		if(unlikely(SvUTF8(top_pathname_sv)))
			SvUTF8_on(sh->top_pathname_sv);
	}
	mode = mode_from_sv(mode_sv);
	sh->mode = mode & (STOREMODE_READ|STOREMODE_WRITE);
	top_pathname_pv = SvPV_nolen(sh->top_pathname_sv);
	sh->u.live.dir = dir = dirref_open(top_pathname_pv, &statbuf);
	if(unlikely(dirref_is_null(dir))) {
		if(!likely(errno == ENOENT && (mode & STOREMODE_CREATE)))
			shash_error_errno(sh, "open");
		if(unlikely(mkdir(top_pathname_pv, S_IRWXU|S_IRWXG|S_IRWXO)
				== -1) &&
				errno != EEXIST)
			shash_error_errno(sh, "open");
		sh->u.live.dir = dir = dirref_open(top_pathname_pv, &statbuf);
		if(unlikely(dirref_is_null(dir))) shash_error_errno(sh, "open");
	}
	if(!likely(S_ISDIR(statbuf.st_mode)))
		shash_open_error_magic(sh);
	dir_iterate(sh, "open", THX_shash_open_check_file, 0);
	master_fd = dirref_via_open_cloexec(dir, MASTER_FILENAME,
			(mode & STOREMODE_WRITE) ? O_RDWR : O_RDONLY, 0);
	if(likely(master_fd != -1)) {
		opened_master:
		fdr = closefd_save(master_fd);
		if(unlikely(mode & STOREMODE_EXCLUDE))
			shash_error_errnum(sh, "open", EEXIST);
		if(unlikely(fstat(master_fd, &statbuf) == -1))
			shash_error_errno(sh, "open");
		if(!likely(S_ISREG(statbuf.st_mode) &&
				(off_t)(word)statbuf.st_size ==
					statbuf.st_size &&
				statbuf.st_size >= MFL_PARAM+WORD_SZ))
			shash_open_error_magic(sh);
		mapsv = mmap_as_sv(master_fd, MFL_PARAM+WORD_SZ, 0);
		if(!likely(mapsv)) shash_error_errno(sh, "open");
		map = mmap_addr_from_sv(mapsv);
		if(!likely(WORD_AT(map, MFL_MAGIC) == MASTER_FILE_MAGIC))
			shash_open_error_magic(sh);
		sh->parameter = WORD_AT(map, MFL_PARAM);
		if(unlikely(PARAMETER_WORD_FIXED_PART(sh->parameter) !=
				PARAMETER_WORD_FIXED_PART_VALUE)) {
			bad_parameter:
			shash_error(sh, "open", "unsupported format");
		}
		sh->sizes = sizes_lookup(sh->parameter);
		if(!likely(sh->sizes)) goto bad_parameter;
		mmap_early_unmap(mapsv);
		if(!likely((word)statbuf.st_size == sh->sizes->mfl_sz))
			shash_open_error_magic(sh);
		mapsv = mmap_as_sv(master_fd, sh->sizes->mfl_sz,
				!!(mode & STOREMODE_WRITE));
		if(!likely(mapsv)) shash_error_errno(sh, "open");
		sh->u.live.master_mmap_sv = SvREFCNT_inc_simple_NN(mapsv);
		sh->u.live.master_mmap = mmap_addr_from_sv(mapsv);
		closefd_early(fdr);
		if(mode & STOREMODE_WRITE)
			dir_clean(sh, "open",
				sync_read_word(&WORD_AT(sh->u.live.master_mmap,
					sh->sizes->mfl_current_datafileid)));
		return shsvref;
	}
	if(!likely(errno == ENOENT && (mode & STOREMODE_CREATE)))
		shash_error_errno(sh, "open");
	sh->parameter = parameter_preferred();
	sh->sizes = sizes_lookup(sh->parameter);
	if(!likely(sh->sizes)) shash_error_errnum(sh, "open", ENOMEM);
	if(unlikely((off_t)sh->sizes->mfl_sz < 0 ||
			(word)(off_t)sh->sizes->mfl_sz != sh->sizes->mfl_sz))
		shash_error_errnum(sh, "open", EFBIG);
	dir_make_temp_filename(temp_filename);
	master_fd = dirref_via_open_cloexec(dir, temp_filename,
			O_RDWR|O_CREAT|O_EXCL,
			S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if(unlikely(master_fd == -1)) shash_error_errno(sh, "open");
	ulr = unlinkfile_save(dir, temp_filename);
	fdr = closefd_save(master_fd);
	if(unlikely(ftruncate(master_fd, sh->sizes->mfl_sz) == -1))
		shash_error_errno(sh, "open");
	mapsv = mmap_as_sv(master_fd, sh->sizes->mfl_sz, 1);
	if(!likely(mapsv)) shash_error_errno(sh, "open");
	sh->u.live.master_mmap_sv = SvREFCNT_inc_simple_NN(mapsv);
	sh->u.live.master_mmap = map = mmap_addr_from_sv(mapsv);
	closefd_early(fdr);
	WORD_AT(map, MFL_MAGIC) = MASTER_FILE_MAGIC;
	WORD_AT(map, MFL_PARAM) = sh->parameter;
	if(unlikely(dirref_via_link(dir, temp_filename, MASTER_FILENAME)
			== -1)) {
		if(unlikely(errno != EEXIST))
			shash_error_errno(sh, "open");
		mmap_early_unmap(mapsv);
		sh->u.live.master_mmap_sv = NULL;
		SvREFCNT_dec_NN(mapsv);
		unlinkfile_early(ulr);
		master_fd = dirref_via_open_cloexec(dir, MASTER_FILENAME,
			(mode & STOREMODE_WRITE) ? O_RDWR : O_RDONLY, 0);
		if(unlikely(master_fd == -1)) shash_error_errno(sh, "open");
		goto opened_master;
	}
	unlinkfile_early(ulr);
	dir_clean(sh, "open", 0);
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

#define pp1_is_shash() THX_pp1_is_shash(aTHX)
static void THX_pp1_is_shash(pTHX)
{
	dSP;
	SETs(boolSV(arg_is_shash(TOPs)));
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
	SV *mode_sv = POPs;
	SV *top_pathname_sv = TOPs;
	PUTBACK;
	sh = shash_open(top_pathname_sv, mode_sv);
	SPAGAIN;
	SETs(sh);
}

#define pp1_shash_is_readable() THX_pp1_shash_is_readable(aTHX)
static void THX_pp1_shash_is_readable(pTHX)
{
	dSP;
	SETs(boolSV(shash_from_svref(TOPs)->mode & STOREMODE_READ));
}

#define pp1_shash_is_writable() THX_pp1_shash_is_writable(aTHX)
static void THX_pp1_shash_is_writable(pTHX)
{
	dSP;
	SETs(boolSV(shash_from_svref(TOPs)->mode & STOREMODE_WRITE));
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
	struct shash *sh;
	struct pvl keypvl;
	SV *resultsv;
	dSP;
	SV *keysv = POPs;
	PUTBACK;
	sh = shash_from_svref(TOPs);
	keypvl = pvl_from_arg("key", 0, keysv);
	shash_check_readable(sh, "read");
	resultsv = boolSV(btree_get(sh, shash_root_for_read(sh), keypvl)
				!= NULL_PTR);
	SPAGAIN;
	SETs(resultsv);
}

#define pp1_shash_get() THX_pp1_shash_get(aTHX)
static void THX_pp1_shash_get(pTHX)
{
	struct shash *sh;
	struct pvl keypvl;
	word valptr;
	SV *valsv;
	dSP;
	SV *keysv = POPs;
	PUTBACK;
	sh = shash_from_svref(TOPs);
	keypvl = pvl_from_arg("key", 0, keysv);
	shash_check_readable(sh, "read");
	valptr = btree_get(sh, shash_root_for_read(sh), keypvl);
	valsv = valptr == NULL_PTR ? &PL_sv_undef :
		string_as_sv(sh, "read", valptr);
	SPAGAIN;
	SETs(valsv);
}

struct mutateargs_set {
	struct pvl keypvl;
	struct pvl newvalpvl;
};

static word THX_mutate_set(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	word oldroot, void *mutate_arg)
{
	struct mutateargs_set *args = (struct mutateargs_set *)mutate_arg;
	return btree_set(sh, alloc, oldroot, args->keypvl, args->newvalpvl);
}

#define pp1_shash_settish(au) THX_pp1_shash_settish(aTHX_ au)
static void THX_pp1_shash_settish(pTHX_ bool allow_undef)
{
	SV *keysv, *newvalsv;
	struct mutateargs_set args;
	struct shash *sh;
	dSP;
	newvalsv = POPs;
	keysv = POPs;
	sh = shash_from_svref(POPs);
	if(unlikely(GIMME_V == G_SCALAR)) PUSHs(&PL_sv_undef);
	PUTBACK;
	args.keypvl = pvl_from_arg("key", 0, keysv);
	args.newvalpvl = pvl_from_arg("new value", allow_undef, newvalsv);
	shash_check_writable(sh, "write");
	shash_mutate(sh, "write", THX_mutate_set, &args);
}

#define pp1_shash_set() THX_pp1_shash_set(aTHX)
PERL_STATIC_INLINE void THX_pp1_shash_set(pTHX)
{
	pp1_shash_settish(1);
}

#define pp1_shash_tied_store() THX_pp1_shash_tied_store(aTHX)
PERL_STATIC_INLINE void THX_pp1_shash_tied_store(pTHX)
{
	pp1_shash_settish(0);
}

struct mutateargs_gset {
	struct pvl keypvl;
	struct pvl newvalpvl;
	word oldvalptr;
};

static word THX_mutate_gset(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	word oldroot, void *mutate_arg)
{
	struct mutateargs_gset *args = (struct mutateargs_gset *)mutate_arg;
	args->oldvalptr = btree_get(sh, oldroot, args->keypvl);
	return btree_set(sh, alloc, oldroot, args->keypvl, args->newvalpvl);
}

#define pp1_shash_gset() THX_pp1_shash_gset(aTHX)
static void THX_pp1_shash_gset(pTHX)
{
	SV *keysv, *newvalsv, *oldvalsv;
	struct mutateargs_gset args;
	struct shash *sh;
	dSP;
	newvalsv = POPs;
	keysv = POPs;
	PUTBACK;
	sh = shash_from_svref(TOPs);
	args.keypvl = pvl_from_arg("key", 0, keysv);
	args.newvalpvl = pvl_from_arg("new value", 1, newvalsv);
	shash_check_readable(sh, "update");
	shash_check_writable(sh, "update");
	shash_mutate(sh, "update", THX_mutate_gset, &args);
	oldvalsv = args.oldvalptr == NULL_PTR ? &PL_sv_undef :
				string_as_sv(sh, "update", args.oldvalptr);
	SPAGAIN;
	SETs(oldvalsv);
}

#define pp1_shash_tied_delete() THX_pp1_shash_tied_delete(aTHX)
PERL_STATIC_INLINE void THX_pp1_shash_tied_delete(pTHX)
{
	dSP;
	XPUSHs(&PL_sv_undef);
	PUTBACK;
	pp1_shash_gset();
}

struct mutateargs_cset {
	struct pvl keypvl;
	struct pvl chkvalpvl;
	struct pvl newvalpvl;
	bool result;
};

static word THX_mutate_cset(pTHX_ struct shash *sh, struct shash_alloc *alloc,
	word oldroot, void *mutate_arg)
{
	struct mutateargs_cset *args = (struct mutateargs_cset *)mutate_arg;
	word oldvalptr = btree_get(sh, oldroot, args->keypvl);
	if(!likely(pvl_is_null(args->chkvalpvl) ? oldvalptr == NULL_PTR :
			oldvalptr != NULL_PTR &&
			string_eq_pvl(sh, oldvalptr, args->chkvalpvl))) {
		args->result = 0;
		return oldroot;
	}
	args->result = 1;
	return btree_set(sh, alloc, oldroot, args->keypvl, args->newvalpvl);
}

#define pp1_shash_cset() THX_pp1_shash_cset(aTHX)
static void THX_pp1_shash_cset(pTHX)
{
	SV *keysv, *chkvalsv, *newvalsv;
	struct mutateargs_cset args;
	struct shash *sh;
	dSP;
	newvalsv = POPs;
	chkvalsv = POPs;
	keysv = POPs;
	PUTBACK;
	sh = shash_from_svref(TOPs);
	args.keypvl = pvl_from_arg("key", 0, keysv);
	args.chkvalpvl = pvl_from_arg("check value", 1, chkvalsv);
	args.newvalpvl = pvl_from_arg("new value", 1, newvalsv);
	shash_check_readable(sh, "update");
	shash_check_writable(sh, "update");
	shash_mutate(sh, "update", THX_mutate_cset, &args);
	SPAGAIN;
	SETs(boolSV(args.result));
}

#define pp1_shash_snapshot() THX_pp1_shash_snapshot(aTHX)
static void THX_pp1_shash_snapshot(pTHX)
{
	SV *snapshsvref;
	dSP;
	SV *shsvref = TOPs;
	struct shash *sh = shash_from_svref(shsvref);
	if(unlikely(sh->mode & STOREMODE_SNAPSHOT)) {
		snapshsvref = sv_2mortal(newRV_inc(SvRV(shsvref)));
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
		snapsh->sizes = sh->sizes;
		snapsh->parameter = sh->parameter;
		snapsh->top_pathname_sv = SvREFCNT_inc_NN(sh->top_pathname_sv);
		snapsh->mode =
			(sh->mode & ~STOREMODE_WRITE) | STOREMODE_SNAPSHOT;
		snapsh->data_mmap_sv = SvREFCNT_inc_NN(sh->data_mmap_sv);
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
	SETs(boolSV(shash_from_svref(TOPs)->mode & STOREMODE_SNAPSHOT));
}

#define pp1_shash_tidy() THX_pp1_shash_tidy(aTHX)
static void THX_pp1_shash_tidy(pTHX)
{
	int tries;
	dSP;
	struct shash *sh = shash_from_svref(POPs);
	if(unlikely(GIMME_V == G_SCALAR)) PUSHs(&PL_sv_undef);
	PUTBACK;
	shash_check_writable(sh, "tidy");
	for(tries = 3; tries--; ) {
		shash_ensure_data_file(sh);
		if(!likely(sh->u.live.data_file_id)) break;
		if(likely(sync_read_word(&WORD_AT(sh->data_mmap,
					sh->sizes->dhd_nextalloc_space)) <
					(sh->data_size >> 1)))
			break;
		if(likely(shash_try_rollover(sh, "tidy", 0) != NULL_PTR)) break;
	}
	dir_clean(sh, "tidy", sh->u.live.data_file_id);
}

/* API operations in pp form for ops */

#ifdef cv_set_call_checker

# define HSM_MAKE_PP(name) \
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
HSM_MAKE_PP(shash_tidy)

#endif /* cv_set_call_checker */

/* API operations as XS function bodies */

#ifndef PERL_ARGS_ASSERT_CROAK_XS_USAGE
static void S_croak_xs_usage(pTHX_ const CV *, const char *);
# define croak_xs_usage(cv, params) S_croak_xs_usage(aTHX_ cv, params)
#endif /* !PERL_ARGS_ASSERT_CROAK_XS_USAGE */

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
HSM_MAKE_XSFUNC(shash_tidy, 1, "shash")

#ifndef PERL_ARGS_ASSERT_CROAK_XS_USAGE
# undef croak_xs_usage
#endif /* !PERL_ARGS_ASSERT_CROAK_XS_USAGE */

/* checker to turn function calls into custom ops */

#ifdef cv_set_call_checker
static OP *THX_ck_entersub_args_hsm(pTHX_ OP *entersubop, GV *namegv, SV *ckobj)
{
	CV *cv = (CV*)ckobj;
	OP *pushop, *firstargop, *cvop, *lastargop, *argop, *newop;
	int nargs;
	entersubop = ck_entersub_args_proto(entersubop, namegv, (SV*)cv);
	pushop = cUNOPx(entersubop)->op_first;
	if(!pushop->op_sibling) pushop = cUNOPx(pushop)->op_first;
	firstargop = pushop->op_sibling;
	for (cvop = firstargop; cvop->op_sibling; cvop = cvop->op_sibling) ;
	lastargop = pushop;
	for (nargs = 0, lastargop = pushop, argop = firstargop; argop != cvop;
			lastargop = argop, argop = argop->op_sibling)
		nargs++;
	if(unlikely(nargs != (int)CvPROTOLEN(cv))) return entersubop;
	pushop->op_sibling = cvop;
	lastargop->op_sibling = NULL;
	op_free(entersubop);
# ifdef XopENTRY_set
	newop = newUNOP(OP_CUSTOM, 0, firstargop);
# else /* !XopENTRY_set */
	newop = newUNOP(OP_NULL, 0, firstargop);
	newop->op_type = OP_DOFILE;
# endif /* !XopENTRY_set */
	newop->op_ppaddr = DPTR2FPTR(Perl_ppaddr_t, CvXSUBANY(cv).any_ptr);
	return newop;
}
#endif /* cv_set_call_checker */

MODULE = Hash::SharedMem PACKAGE = Hash::SharedMem

PROTOTYPES: DISABLE

BOOT:
{
	dirref_ensure_strategy();
	(void) newCONSTSUB(NULL, "Hash::SharedMem::shash_referential_handle",
		boolSV(dirref_referential()));
}

BOOT:
	sizes_table = ptr_table_new();

BOOT:
	shash_handle_stash = gv_stashpvs("Hash::SharedMem::Handle", 1);

BOOT:
{
#ifdef cv_set_call_checker
# define PPFUNC_(name) THX_pp_##name,
#else /* !cv_set_call_checker */
# define PPFUNC_(name) /**/
#endif /* !cv_set_call_checker */
#define HSM_FUNC_TO_INSTALL(name, arity) \
		{ \
			"Hash::SharedMem::"#name, \
			PPFUNC_(name) \
			THX_xsfunc_##name, \
			(arity), \
		}
	struct {
		char const *fqsubname;
#ifdef cv_set_call_checker
		Perl_ppaddr_t THX_pp;
#endif /* cv_set_call_checker */
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
		HSM_FUNC_TO_INSTALL(shash_tidy, 1),
	}, *fti;
	int i;
	for(i = C_ARRAY_LENGTH(funcs_to_install); i--; ) {
		CV *fcv;
#if defined(cv_set_call_checker) && defined(XopENTRY_set)
		XOP *xop;
		char const *shortname;
#endif /* cv_set_call_checker && XopENTRY_set */
		fti = &funcs_to_install[i];
		fcv = newXSproto_portable((char*)fti->fqsubname,
			fti->THX_xsfunc, __FILE__, "$$$$"+4-fti->arity);
#ifdef cv_set_call_checker
# ifdef XopENTRY_set
		Newxz(xop, 1, XOP);
		shortname = fti->fqsubname + sizeof("Hash::SharedMem::")-1;
		XopENTRY_set(xop, xop_name, shortname);
		XopENTRY_set(xop, xop_desc, shortname);
		XopENTRY_set(xop, xop_class, OA_UNOP);
		Perl_custom_op_register(aTHX_ fti->THX_pp, xop);
# endif /* XopENTRY_set */
		CvXSUBANY(fcv).any_ptr = FPTR2DPTR(void*, fti->THX_pp);
		cv_set_call_checker(fcv, THX_ck_entersub_args_hsm, (SV*)fcv);
#else /* !cv_set_call_checker */
		PERL_UNUSED_VAR(fcv);
#endif /* !cv_set_call_checker */
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
		if(likely(sh->u.live.master_mmap_sv))
			SvREFCNT_dec_NN(sh->u.live.master_mmap_sv);
		if(likely(!dirref_is_null(sh->u.live.dir)))
			dirref_close(sh->u.live.dir);
	}
	if(likely(sh->top_pathname_sv)) SvREFCNT_dec_NN(sh->top_pathname_sv);
	if(likely(sh->data_mmap_sv)) SvREFCNT_dec_NN(sh->data_mmap_sv);

SV *
open(SV *classname, SV *filename, SV *mode)
CODE:
	PERL_UNUSED_VAR(classname);
	PUTBACK;
	RETVAL = shash_open(filename, mode);
	SvREFCNT_inc_simple_void_NN(RETVAL);
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
				!(klen == 24 &&
					memcmp(kpv+6, "referential_handle", 18)
							== 0) &&
				!(klen == 10 && memcmp(kpv+6, "open", 4) == 0))
			(void) hv_store(mstash, kpv+6, klen-6,
					SvREFCNT_inc_NN(HeVAL(he)), 0);
	}
}

SV *
TIEHASH(SV *classname, SV *arg0, SV *arg1 = NULL)
CODE:
	PERL_UNUSED_VAR(classname);
	if(!arg1) {
		arg_check_shash(arg0);
		RETVAL = newRV_inc(SvRV(arg0));
	} else {
		PUTBACK;
		RETVAL = shash_open(arg0, arg1);
		SvREFCNT_inc_simple_void_NN(RETVAL);
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
	(void) pvl_from_arg("key", 0, lastkey);
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
		SvREFCNT_inc_NN(*hv_fetchs(mstash, "getd", 0)));
	(void) hv_stores(mstash, "FETCH",
		SvREFCNT_inc_NN(*hv_fetchs(mstash, "get", 0)));
	(void) newXSproto_portable("Hash::SharedMem::Handle::STORE",
		THX_xsfunc_shash_tied_store, __FILE__, "$$$");
	(void) newXSproto_portable("Hash::SharedMem::Handle::DELETE",
		THX_xsfunc_shash_tied_delete, __FILE__, "$$");
}
