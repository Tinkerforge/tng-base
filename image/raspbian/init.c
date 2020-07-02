//
// TNG Base Raspberry Pi CMX Image
// Copyright (C) 2020 Matthias Bolte <matthias@tinkerforge.com>
//

// http://landley.net/writing/rootfs-howto.html
// https://wiki.gentoo.org/wiki/Custom_Initramfs
// http://jootamam.net/howto-initramfs-image.htm
// https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt
// http://git.busybox.net/busybox/tree/util-linux/switch_root.c
// http://www.stlinux.com/howto/initramfs

#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <crypt.h>

#define USERNAME "tng"
#define DEFAULT_PASSWORD "default-tng-password"
#define SHADOW_PATH "/root/etc/shadow"
#define SHADOW_BACKUP_PATH SHADOW_PATH"-"
#define SHADOW_TMP_PATH SHADOW_PATH"+"
#define SHADOW_BUFFER_LENGTH (512 * 1024)
#define SHADOW_ENCRYPTED_LENGTH 512
#define ENTROPY_LENGTH 16
#define SALT_PREFIX "$6$"

static int kmsg_fd = -1;
static const char salt_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

static void print(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void panic(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void vprint(const char *format, va_list ap)
{
	char message[512];
	char buffer[512];
	int ignored;

	vsnprintf(message, sizeof(message), format, ap);

	if (kmsg_fd < 0) {
		printf("initramfs: %s\n", message);
	} else {
		snprintf(buffer, sizeof(buffer), "initramfs: %s\n", message);

		ignored = write(kmsg_fd, buffer, strlen(buffer)); // FIXME: error handling

		(void)ignored;
	}
}

static void print(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprint(format, ap);
	va_end(ap);
}

static void panic(const char *format, ...)
{
	va_list ap;
	FILE *fp;
	int i;

	if (format != NULL) {
		va_start(ap, format);
		vprint(format, ap);
		va_end(ap);
	}

	// ensure /proc is mounted
	if (mkdir("/proc", 0775) < 0) {
		if (errno != EEXIST) {
			print("creating /proc failed");
		} else {
			errno = 0; // don't leak errno
		}
	}

	if (mount("proc", "/proc", "proc", 0, "") < 0) {
		if (errno != EBUSY) {
			print("mounting proc at /proc failed");
		} else {
			errno = 0; // don't leak errno
		}
	}

	// wait 30 seconds
	print("triggering reboot in 30 sec");
	sleep(10);

	print("triggering reboot in 20 sec");
	sleep(10);

	print("triggering reboot in 10 sec");
	sleep(5);

	for (i = 5; i > 0; --i) {
		print("triggering reboot in %d sec", i);
		sleep(1);
	}

	// trigger reboot
	fp = fopen("/proc/sysrq-trigger", "wb");

	if (fp == NULL) {
		print("opening /proc/sysrq-trigger failed, cannot trigger reboot");
	}

	if (fwrite("b\n", 1, 2, fp) != 2) {
		print("writing to /proc/sysrq-trigger failed, cannot trigger reboot");
	}

	fclose(fp);
	print("reboot triggered");

	// wait for reboot to happen
	while (true) {
		sleep(1000);
	}
}

static void robust_mount(const char *source, const char *target, const char *type, unsigned long flags)
{
	size_t retries = 0;

	print("mounting %s at %s", source, target);

	while (mount(source, target, type, flags, "") < 0) {
		if (errno == ENXIO) {
			print("mounting %s at %s failed, trying again in 250 msec", source, target);
			usleep(250 * 1000);

			errno = 0; // clear errno, so it doesn't leak if the next mount try succeeds
			++retries;
		} else {
			panic("mounting %s at %s failed: %s (%d)", source, target, strerror(errno), errno);
		}
	}

	if (retries > 0) {
		print("mounting %s at %s succeeded after %zu %s", source, target, retries, retries == 1 ? "retry" : "retries");
	}
}

static int create_file(char *path, uid_t uid, gid_t gid, mode_t mode)
{
	int fd;

	print("creating %s", path);

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

	if (fd < 0) {
		panic("could not create %s for writing: %s (%d)", path, strerror(errno), errno);
	}

	if (fchown(fd, uid, gid) < 0) {
		panic("could not change owner of %s: %s (%d)", path, strerror(errno), errno);
	}

	if (fchmod(fd, mode) < 0) {
		panic("could not change mode of %s: %s (%d)", path, strerror(errno), errno);
	}

	return fd;
}

static void robust_write(const char *path, int fd, const void *buffer, size_t buffer_length)
{
	ssize_t length = write(fd, buffer, buffer_length);

	if (length < 0) {
		panic("could not write to %s: %s (%d)", path, strerror(errno), errno);
	}

	if ((size_t)length < buffer_length) {
		panic("short write to %s: %s (%d)", path, strerror(errno), errno);
	}
}

static void change_password(void)
{
	int fd;
	struct stat st;
	char *buffer;
	size_t buffer_used;
	ssize_t length;
	char *entry_begin;
	char *encrypted_begin;
	char *encrypted_end;
	char encrypted[SHADOW_ENCRYPTED_LENGTH];
	size_t encrypted_used;
	char salt[SHADOW_ENCRYPTED_LENGTH]; // over-allocate to be safe
	size_t salt_used;
	char *encrypted_prefix_end;
	struct crypt_data crypt_data;
	const char *crypt_result;
	char entropy[ENTROPY_LENGTH];
	ssize_t entropy_length;
	size_t salt_prefix_length = strlen(SALT_PREFIX);
	size_t i;

	crypt_data.initialized = 0;

	// open /etc/shadow
	print("opening %s", SHADOW_PATH);

	fd = open(SHADOW_PATH, O_RDONLY);

	if (fd < 0) {
		panic("could not open %s for reading: %s (%d)", SHADOW_PATH, strerror(errno), errno);
	}

	if (fstat(fd, &st) < 0) {
		panic("could not get status of %s: %s (%d)", SHADOW_PATH, strerror(errno), errno);
	}

	if (st.st_size > SHADOW_BUFFER_LENGTH) {
		panic("%s is too big", SHADOW_PATH);
	}

	// read /etc/shadow
	print("reading %s", SHADOW_PATH);

	buffer_used = st.st_size;
	buffer = malloc(buffer_used + 1); // +1 for NULL terminator

	if (buffer == NULL) {
		panic("could not allocate memory");
	}

	length = read(fd, buffer, buffer_used);

	if (length < 0) {
		panic("could not read from %s: %s (%d)", SHADOW_PATH, strerror(errno), errno);
	}

	if ((size_t)length < buffer_used) {
		panic("short read from %s: %s (%d)", SHADOW_PATH, strerror(errno), errno);
	}

	buffer[buffer_used] = '\0';

	print("closing %s", SHADOW_PATH);

	close(fd);

	// find entry for username
	if (strncmp(buffer, USERNAME":", strlen(USERNAME":")) == 0) {
		entry_begin = buffer;
	} else {
		entry_begin = strstr(buffer, "\n"USERNAME":");

		if (entry_begin == NULL) {
			print("username %s not present, skipping password replacement", USERNAME);

			goto cleanup;
		}

		++entry_begin; // skip new-line
	}

	// find encrypted section in entry
	encrypted_begin = strchr(entry_begin, ':');

	if (encrypted_begin == NULL) {
		panic("encrypted section for username %s is malformed", USERNAME);
	}

	++encrypted_begin; // skip colon
	encrypted_end = strchr(encrypted_begin, ':');

	if (encrypted_end == NULL) {
		panic("encrypted section for username %s is malformed", USERNAME);
	}

	encrypted_used = encrypted_end - encrypted_begin;

	if (encrypted_used > SHADOW_ENCRYPTED_LENGTH) {
		panic("encrypted section for username %s is too big", USERNAME);
	}

	memcpy(encrypted, encrypted_begin, encrypted_used);

	encrypted[encrypted_used] = '\0';

	// get salt from encrypted section
	if (encrypted[0] == '!' || encrypted[0] == '*') {
		print("username %s does not use default password, skipping password replacement", USERNAME);

		goto cleanup;
	}

	if (encrypted_used < 2) {
		panic("encrypted section for username %s is malformed", USERNAME);
	}

	if (encrypted[0] != '$') {
		salt_used = 2;
	} else {
		encrypted_prefix_end = strrchr(encrypted, '$');

		if (encrypted_prefix_end == NULL) {
			panic("encrypted section for username %s is malformed", USERNAME);
		}

		salt_used = encrypted_prefix_end - encrypted;
	}

	memcpy(salt, encrypted, salt_used);

	salt[salt_used] = '\0';

	// encrypt default password with salt from encrypted section
	crypt_result = crypt_r(DEFAULT_PASSWORD, salt, &crypt_data);

	if (crypt_result == NULL) {
		panic("could not encrypt default password: %s (%d)", strerror(errno), errno);
	}

	if (strcmp(crypt_result, encrypted) != 0) {
		print("username %s does not have the default password set, skipping password replacement", USERNAME);

		goto cleanup;
	}

	print("username %s has the default password set, replacing password", USERNAME);

	// get random salt
	print("collecting entropy");

	entropy_length = getrandom(entropy, ENTROPY_LENGTH, 0);

	if (entropy_length < 0) {
		panic("could not collect entropy: %s (%d)", strerror(errno), errno);
	}

	if (entropy_length < ENTROPY_LENGTH) {
		panic("could not collect enough entropy");
	}

	memcpy(salt, SALT_PREFIX, salt_prefix_length);

	salt_used = salt_prefix_length;

	for (i = 0; i < ENTROPY_LENGTH; ++i) {
		salt[salt_used++] = salt_chars[entropy[i] % (sizeof(salt_chars) - 1)];
	}

	salt[salt_used] = '\0';

	// encrypt device specific password
	print("encrypting device specific password");

	crypt_result = crypt_r("foobar", salt, &crypt_data); // FIXME: use device specific password

	if (crypt_result == NULL) {
		panic("could not encrypt device specific password: %s (%d)", strerror(errno), errno);
	}

	// create /etc/shadow-
	fd = create_file(SHADOW_BACKUP_PATH, st.st_uid, st.st_gid, st.st_mode);

	robust_write(SHADOW_BACKUP_PATH, fd, buffer, buffer_used);

	print("closing %s", SHADOW_BACKUP_PATH);

	fsync(fd);
	close(fd);

	// create /etc/shadow+
	fd = create_file(SHADOW_TMP_PATH, st.st_uid, st.st_gid, st.st_mode);

	robust_write(SHADOW_TMP_PATH, fd, buffer, encrypted_begin - buffer);
	robust_write(SHADOW_TMP_PATH, fd, crypt_result, strlen(crypt_result));
	robust_write(SHADOW_TMP_PATH, fd, encrypted_end, buffer_used - (encrypted_end - buffer));

	print("closing %s", SHADOW_TMP_PATH);

	fsync(fd);
	close(fd);

	// rename /etc/shadow+ to /etc/shadow
	print("renaming %s to %s", SHADOW_TMP_PATH, SHADOW_PATH);

	if (rename(SHADOW_TMP_PATH, SHADOW_PATH) < 0) {
		panic("could not rename %s to %s: %s (%d)", SHADOW_TMP_PATH, SHADOW_PATH, strerror(errno), errno);
	}

cleanup:
	free(buffer);
}

int main(void)
{
	const char *execv_argv[] = {
		"/sbin/init",
		NULL
	};

	// open /dev/kmsg
	kmsg_fd = open("/dev/kmsg", O_WRONLY);

	// mount /proc
	print("mounting proc at /proc");

	if (mount("proc", "/proc", "proc", 0, "") < 0) {
		panic("mounting proc at /proc failed: %s (%d)", strerror(errno), errno);
	}

	// mount /sys
	print("mounting sysfs at /sys");

	if (mount("sysfs", "/sys", "sysfs", 0, "") < 0) {
		panic("mounting sysfs at /sys failed: %s (%d)", strerror(errno), errno);
	}

	// mount /dev/mmcblk0p2 (root)
	robust_mount("/dev/mmcblk0p2", "/root", "ext4", MS_NOATIME);

	// change password if necessary
	change_password();

	// unmount /proc
	print("unmounting /proc");

	if (umount("/proc") < 0) {
		panic("unmounting /proc failed: %s (%d)", strerror(errno), errno);
	}

	// unmount /sys
	print("unmounting /sys");

	if (umount("/sys") < 0) {
		panic("unmounting /sys failed: %s (%d)", strerror(errno), errno);
	}

	// switch root (logic taken from busybox switch_root and simplified)
	print("preparing root-mount switch");

	if (chdir("/root") < 0) {
		panic("changing current directory to new root-mount failed: %s (%d)", strerror(errno), errno);
	}

	unlink("/init"); // unlink ourself to free some memory

	if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
		panic("moving root-mount failed: %s (%d)", strerror(errno), errno);
	}

	if (chroot(".") < 0) {
		panic("chrooting into moved root-mount failed: %s (%d)", strerror(errno), errno);
	}

	if (chdir("/") < 0) {
		panic("changing current directory to moved root-mount failed: %s (%d)", strerror(errno), errno);
	}

	// execute /sbin/init
	print("executing /sbin/init in new root-mount");

	if (kmsg_fd >= 0) {
		close(kmsg_fd);

		kmsg_fd = -1;
	}

	execv(execv_argv[0], (char **)execv_argv);

	panic("executing /sbin/init in new root-mount failed: %s (%d)", strerror(errno), errno);

	return EXIT_FAILURE; // unreachable
}
