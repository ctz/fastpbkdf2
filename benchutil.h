/* nb. this is not a real header file; its just for sharing code between
 * bench.c and benchmulti.c.
 * 
 * It results in typedefs: proctime (process user CPU time)
 * And functions:
 * - cpu_now (current process user CPU time, return type proctime)
 * - proctime2secs (difference between two CPU times, in seconds)
 * - wall_now (wall time, in seconds vs some epoch; as a double)
 */

#ifdef _MSC_VER
/* Windows */
#include <windows.h>

typedef FILETIME proctime;

static FILETIME cpu_now(void)
{
  FILETIME create, exit, kernel, user;
  BOOL rc = GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user);
  assert(rc);
  return user;
}

static double proctime2secs(FILETIME start, FILETIME end)
{
  ULARGE_INTEGER start_ll, end_ll;
  start_ll.LowPart = start.dwLowDateTime;
  start_ll.HighPart = start.dwHighDateTime;
  end_ll.LowPart = end.dwLowDateTime;
  end_ll.HighPart = end.dwHighDateTime;
  
  assert(end_ll.QuadPart >= start_ll.QuadPart);
  
  return (end_ll.QuadPart - start_ll.QuadPart) * 100e-9;
}

static double wall_now(void)
{
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  
  ULARGE_INTEGER ll;
  ll.LowPart = ft.dwLowDateTime;
  ll.HighPart = ft.dwHighDateTime;
  return ll.QuadPart * 100e-9;
}
#else
/* Not windows */
#include <unistd.h>
#include <sys/time.h>
#include <sys/times.h>

typedef clock_t proctime;

static clock_t cpu_now(void)
{
  struct tms tms;
  times(&tms);
  return tms.tms_utime;
}

static double proctime2secs(clock_t start, clock_t end)
{
  assert(end >= start);
  return (end - start) / (double) sysconf(_SC_CLK_TCK);
}

static double wall_now(void)
{
  struct timeval tv = { 0, 0 };
  gettimeofday(&tv, NULL);
  double r = tv.tv_sec;
  r += (double) tv.tv_usec * 1e-6;
  return r;
}
#endif