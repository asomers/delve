#include <sys/types.h>
#include <libutil.h>
#include "proc_darwin.h"

char *
find_executable(int pid) {
	char *command_name = NULL;
	struct kinfo_proc *kinfo;

	kinfo = kinfo_getproc(pid);
	if (kinfo != NULL) {
		command_name = malloc(COMMLEN + 1);
		if (command_name != NULL) {
			strlcpy(command_name, kinfo->ki_comm, COMMLEN + 1);
		}
		free(kinfo);
	}

	return command_name;
}
