//
// TNG Base Raspberry Pi CMX Image
// Copyright (C) 2020 Matthias Bolte <matthias@tinkerforge.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include <sys/utsname.h>
#include <libkmod.h>
#include <zlib.h>
#include <sys/ioctl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#define EEPROM_PATH "/dev/i2c-1"
#define EEPROM_ADDRESS 0x50
#define EEPROM_MAGIC_NUMBER 0x21474E54
#define ACCOUNT_NAME "tng"
#define DEFAULT_PASSWORD "default-tng-password"
#define SHADOW_PATH "/mnt/etc/shadow"
#define SHADOW_BACKUP_PATH SHADOW_PATH"-"
#define SHADOW_TMP_PATH SHADOW_PATH"+"
#define SHADOW_BUFFER_LENGTH (512 * 1024)
#define SHADOW_ENCRYPTED_LENGTH 512

typedef struct {
	uint32_t magic_number; // magic number 0x21474E54 (TNG!)
	uint32_t checksum; // zlib CRC32 checksum over all following bytes
	uint16_t data_length; // length of data blocks in byte
	uint8_t data_version; // indicating the available data blocks
} __attribute__((packed)) EEPROM_Header;

typedef struct {
	char uid[7]; // null-terminated unique identifier, exposed at /etc/tng-base-uid
	char hostname[65]; // null-terminated /etc/hostname entry
	char encrypted_password[107]; // null-terminated /etc/shadow password entry
	uint8_t ethernet_config[512]; // config for Ethernet chip
} __attribute__((packed)) EEPROM_DataV1;

typedef struct {
	EEPROM_Header header;
	EEPROM_DataV1 data_v1;
} __attribute__((packed)) EEPROM;

static int kmsg_fd = -1;
static EEPROM eeprom;
static bool eeprom_valid = false;

static void print(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void panic(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void vprint(const char *prefix, const char *format, va_list ap)
{
	char message[512];
	char buffer[512];
	int ignored;

	vsnprintf(message, sizeof(message), format, ap);

	if (kmsg_fd < 0) {
		printf("initramfs: %s%s\n", prefix, message);
	} else {
		snprintf(buffer, sizeof(buffer), "initramfs: %s%s\n", prefix, message);

		ignored = write(kmsg_fd, buffer, strlen(buffer)); // FIXME: error handling

		(void)ignored;
	}
}

static void print(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprint("", format, ap);
	va_end(ap);
}

static void error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprint("error: ", format, ap);
	va_end(ap);
}

static void panic(const char *format, ...)
{
	va_list ap;
	FILE *fp;
	int i;

	if (format != NULL) {
		va_start(ap, format);
		vprint("panic: ", format, ap);
		va_end(ap);
	}

	// ensure /proc is mounted
	if (mkdir("/proc", 0775) < 0) {
		if (errno != EEXIST) {
			error("could not create /proc: %s (%d)", strerror(errno), errno);
		} else {
			errno = 0; // don't leak errno
		}
	}

	if (mount("proc", "/proc", "proc", 0, "") < 0) {
		if (errno != EBUSY) {
			error("could not mount proc at /proc: %s (%d)", strerror(errno), errno);
		} else {
			errno = 0; // don't leak errno
		}
	}

	// wait 60 seconds
	print("triggering reboot in 60 sec");
	sleep(50);

	print("triggering reboot in 10 sec");
	sleep(5);

	for (i = 5; i > 0; --i) {
		print("triggering reboot in %d sec", i);
		sleep(1);
	}

	// trigger reboot
	fp = fopen("/proc/sysrq-trigger", "wb");

	if (fp == NULL) {
		error("could not open /proc/sysrq-trigger for writing: %s (%d)", strerror(errno), errno);
	} else {
		if (fwrite("b\n", 1, 2, fp) != 2) {
			error("could not write reboot request to /proc/sysrq-trigger");
		} else {
			print("reboot triggered");
		}

		fclose(fp);
	}

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
			error("could not mount %s at %s, device is missing, trying again in 250 msec", source, target);
			usleep(250 * 1000);

			errno = 0; // clear errno, so it doesn't leak if the next mount try succeeds
			++retries;
		} else {
			panic("could not mount %s at %s: %s (%d)", source, target, strerror(errno), errno);
		}
	}

	if (retries > 0) {
		print("succssfully mounted %s at %s after %zu %s", source, target, retries, retries == 1 ? "retry" : "retries");
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
		panic("could not change owner of %s to %u:%u: %s (%d)", path, uid, gid, strerror(errno), errno);
	}

	if (fchmod(fd, mode) < 0) {
		panic("could not change mode of %s to 0o%03o: %s (%d)", path, mode, strerror(errno), errno);
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

static void modprobe(const char *name)
{
	int rc;
	struct utsname utsname;
	char base[128];
	struct kmod_ctx *ctx;
	struct kmod_list *list = NULL;
	struct kmod_list *iter;
	struct kmod_module *module;

	print("loading kernel module %s", name);

	rc = uname(&utsname);

	if (rc < 0) {
		panic("could not get kernel release: %s (%d)", strerror(errno), errno);
	}

	snprintf(base, sizeof(base), "/mnt/lib/modules/%s", utsname.release);

	ctx = kmod_new(base, NULL);

	if (ctx == NULL) {
		panic("could not create kmod context");
	}

	rc = kmod_module_new_from_lookup(ctx, name, &list);

	if (rc < 0) {
		panic("could not lookup kernel module %s: %s (%d)", name, strerror(-rc), -rc);
	}

	if (list == NULL) {
		panic("kernel module %s is missing", name);
	}

	kmod_list_foreach(iter, list) {
		module = kmod_module_get_module(iter);
		rc = kmod_module_probe_insert_module(module, 0, NULL, NULL, NULL, NULL);

		if (rc < 0) {
			panic("could not load kernel module %s: %s (%d)", name, strerror(-rc), -rc);
		}

		kmod_module_unref(module);
	}

	kmod_module_unref_list(list);
}

static int i2c_write16(int fd, uint8_t byte0, uint8_t byte1)
{
	struct i2c_smbus_ioctl_data args;
	union i2c_smbus_data data;

	args.read_write = I2C_SMBUS_WRITE;
	args.command = byte0;
	args.size = I2C_SMBUS_BYTE_DATA;
	args.data = &data;

	data.byte = byte1;

	ioctl(fd, BLKFLSBUF);

	return ioctl(fd, I2C_SMBUS, &args);
}

static int i2c_read8(int fd, uint8_t *byte)
{
	struct i2c_smbus_ioctl_data args;
	union i2c_smbus_data data;
	int rc;

	args.read_write = I2C_SMBUS_READ;
	args.command = 0;
	args.size = I2C_SMBUS_BYTE;
	args.data = &data;

	ioctl(fd, BLKFLSBUF);

	rc = ioctl(fd, I2C_SMBUS, &args);

	if (rc < 0) {
		return rc;
	}

	*byte = data.byte & 0xFF;

	return 0;
}

static void read_eeprom(void)
{
	int fd;
	size_t address;
	union {
		EEPROM eeprom;
		uint8_t bytes[sizeof(EEPROM)];
	} u;
	uint8_t byte;
	uint32_t checksum;

	eeprom_valid = false;

	// open I2C bus
	print("opening %s", EEPROM_PATH);

	fd = open(EEPROM_PATH, O_RDWR);

	if (fd < 0) {
		error("could not open %s: %s (%d)", EEPROM_PATH, strerror(errno), errno);

		return;
	}

	// set slave address
	if (ioctl(fd, I2C_SLAVE, EEPROM_ADDRESS) < 0) {
		error("could not set EEPROM slave address to 0x%02X: %s (%d)", EEPROM_ADDRESS, strerror(errno), errno);
		close(fd);

		return;
	}

	// set read address to 0
	if (i2c_write16(fd, 0, 0) < 0) {
		error("could not set EEPROM read address to zero: %s (%d)", strerror(errno), errno);
		close(fd);

		return;
	}

	// read header
	print("reading EEPROM header");

	for (address = 0; address < sizeof(u.eeprom.header); ++address) {
		if (i2c_read8(fd, &u.bytes[address]) < 0) {
			error("could not read EEPROM header at address %zu: %s (%d)", address, strerror(errno), errno);
			close(fd);

			return;
		}
	}

	if (u.eeprom.header.magic_number != EEPROM_MAGIC_NUMBER) {
		error("EEPROM header has wrong magic number: %08X (actual) != %08X (expected)", u.eeprom.header.magic_number, EEPROM_MAGIC_NUMBER);
		close(fd);

		return;
	}

	// read data
	print("reading EEPROM data");

	checksum = crc32(0, Z_NULL, 0);
	checksum = crc32(checksum, (uint8_t *)&u.eeprom.header.data_length, sizeof(u.eeprom.header.data_length));
	checksum = crc32(checksum, (uint8_t *)&u.eeprom.header.data_version, sizeof(u.eeprom.header.data_version));

	for (address = sizeof(u.eeprom.header); address < sizeof(u.eeprom.header) + u.eeprom.header.data_length; ++address) {
		if (i2c_read8(fd, &byte) < 0) {
			error("could not read EEPROM data at address %zu: %s (%d)", address, strerror(errno), errno);
			close(fd);

			return;
		}

		if (address < sizeof(u.eeprom)) {
			u.bytes[address] = byte;
		}

		checksum = crc32(checksum, &byte, sizeof(byte));
	}

	print("closing %s", EEPROM_PATH);

	close(fd);

	// check header and data
	if (u.eeprom.header.checksum != checksum) {
		error("EEPROM header/data has wrong checksum: %08X (actual) != %08X (expected)", checksum, u.eeprom.header.checksum);

		return;
	}

	if (u.eeprom.header.data_version < 1) {
		error("EEPROM header has invalid data-version: %u (actual) < 1 (expected)", u.eeprom.header.data_version);

		return;
	}

	if (u.eeprom.header.data_version == 1 && u.eeprom.header.data_length < sizeof(u.eeprom.data_v1)) {
		error("EEPROM header has invalid data-length: %u (actual) < %u (expected)", u.eeprom.header.data_length, sizeof(u.eeprom.data_v1));

		return;
	}

	if (u.eeprom.data_v1.uid[sizeof(u.eeprom.data_v1.uid) - 1] != '\0') {
		error("EEPROM data uid is not null-terminated");

		return;
	}

	if (u.eeprom.data_v1.hostname[sizeof(u.eeprom.data_v1.hostname) - 1] != '\0') {
		error("EEPROM data hostname is not null-terminated");

		return;
	}

	if (u.eeprom.data_v1.encrypted_password[sizeof(u.eeprom.data_v1.encrypted_password) - 1] != '\0') {
		error("EEPROM data encrypted-password is not null-terminated");

		return;
	}

	memcpy(&eeprom, &u.eeprom, sizeof(eeprom));

	eeprom_valid = true;
}

static void replace_password(void)
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

	if (!eeprom_valid || eeprom.header.data_version < 1) {
		error("required EEPROM data not available, skipping password replacement");

		return;
	}

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
	buffer = malloc(buffer_used + 1); // +1 for null-terminator

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

	// find entry for account
	if (strncmp(buffer, ACCOUNT_NAME":", strlen(ACCOUNT_NAME":")) == 0) {
		entry_begin = buffer;
	} else {
		entry_begin = strstr(buffer, "\n"ACCOUNT_NAME":");

		if (entry_begin == NULL) {
			print("account %s is not present, skipping password replacement", ACCOUNT_NAME);

			goto cleanup;
		}

		++entry_begin; // skip new-line
	}

	// find encrypted section in entry
	encrypted_begin = strchr(entry_begin, ':');

	if (encrypted_begin == NULL) {
		panic("encrypted section for account %s is malformed", ACCOUNT_NAME);
	}

	++encrypted_begin; // skip colon

	if (encrypted_begin[0] == '*') {
		print("account %s has no password set, skipping password replacement", ACCOUNT_NAME);

		goto cleanup;
	}

	if (encrypted_begin[0] != '!') {
		print("account %s is not locked, skipping password replacement", ACCOUNT_NAME);

		goto cleanup;
	}

	encrypted_end = strchr(encrypted_begin, ':');

	if (encrypted_end == NULL) {
		panic("encrypted section for account %s is malformed", ACCOUNT_NAME);
	}

	encrypted_used = encrypted_end - (encrypted_begin + 1); // +1 to skip exclamation mark

	if (encrypted_used > SHADOW_ENCRYPTED_LENGTH) {
		panic("encrypted section for account %s is too big", ACCOUNT_NAME);
	}

	memcpy(encrypted, encrypted_begin + 1, encrypted_used); // +1 to skip exclamation mark

	encrypted[encrypted_used] = '\0';

	// get salt from encrypted section
	if (encrypted_used < 2) {
		panic("encrypted section for account %s is malformed", ACCOUNT_NAME);
	}

	if (encrypted[0] != '$') {
		salt_used = 2;
	} else {
		encrypted_prefix_end = strrchr(encrypted, '$');

		if (encrypted_prefix_end == NULL) {
			panic("encrypted section for account %s is malformed", ACCOUNT_NAME);
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
		print("account %s does not have the default password set, skipping password replacement", ACCOUNT_NAME);

		goto cleanup;
	}

	print("account %s has default password set, replacing with device specific password", ACCOUNT_NAME);

	// create /etc/shadow-
	fd = create_file(SHADOW_BACKUP_PATH, st.st_uid, st.st_gid, st.st_mode);

	robust_write(SHADOW_BACKUP_PATH, fd, buffer, buffer_used);

	print("closing %s", SHADOW_BACKUP_PATH);

	fsync(fd);
	close(fd);

	// create /etc/shadow+
	fd = create_file(SHADOW_TMP_PATH, st.st_uid, st.st_gid, st.st_mode);

	robust_write(SHADOW_TMP_PATH, fd, buffer, encrypted_begin - buffer);
	robust_write(SHADOW_TMP_PATH, fd, eeprom.data_v1.encrypted_password, strlen(eeprom.data_v1.encrypted_password));
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
		panic("could not mount proc at /proc: %s (%d)", strerror(errno), errno);
	}

	// mount /sys
	print("mounting sysfs at /sys");

	if (mount("sysfs", "/sys", "sysfs", 0, "") < 0) {
		panic("could not mount sysfs at /sys: %s (%d)", strerror(errno), errno);
	}

	// wait 250 ms for the device to show up before trying to mount it to avoid
	// an initial warning about the device not being available yet
	usleep(250 * 1000);

	// mount /dev/mmcblk0p2 (root)
	// FIXME: use /proc/cmdline root an rootfstype instead?
	robust_mount("/dev/mmcblk0p2", "/mnt", "ext4", MS_NOATIME);

	// read eeprom content
	modprobe("i2c_bcm2835");
	modprobe("i2c_dev");
	read_eeprom();

	// replace password if necessary
	replace_password();

	// unmount /proc
	print("unmounting /proc");

	if (umount("/proc") < 0) {
		panic("could not unmount /proc: %s (%d)", strerror(errno), errno);
	}

	// unmount /sys
	print("unmounting /sys");

	if (umount("/sys") < 0) {
		panic("could not unmount /sys: %s (%d)", strerror(errno), errno);
	}

	// switch root (logic taken from busybox switch_root and simplified)
	print("switching root-mount to /mnt");

	if (chdir("/mnt") < 0) {
		panic("could not change current directory to /mnt: %s (%d)", strerror(errno), errno);
	}

	unlink("/init"); // unlink ourself to free some memory

	if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
		panic("could not move root-mount: %s (%d)", strerror(errno), errno);
	}

	if (chroot(".") < 0) {
		panic("could not chroot into /mnt: %s (%d)", strerror(errno), errno);
	}

	if (chdir("/") < 0) {
		panic("could not change current directory to /: %s (%d)", strerror(errno), errno);
	}

	// execute /sbin/init
	print("executing /sbin/init in /mnt");

	if (kmsg_fd >= 0) {
		close(kmsg_fd);

		kmsg_fd = -1;
	}

	execv(execv_argv[0], (char **)execv_argv);

	panic("could not execute /sbin/init in /mnt: %s (%d)", strerror(errno), errno);

	return EXIT_FAILURE; // unreachable
}
