#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define SYS_CALL_NUM 13
typedef bool (*SYS_WRAPPER)(struct intr_frame *);

/* System calls wrappers used to facilitate
   the SYSCALL_HANDLER  execution. */
static bool halt_handler(struct intr_frame *);
static bool exit_handler(struct intr_frame *);
static bool exec_handler(struct intr_frame *);
static bool wait_handler(struct intr_frame *);
static bool create_handler(struct intr_frame *);
static bool remove_handler(struct intr_frame *);
static bool open_handler(struct intr_frame *);
static bool filesize_handler(struct intr_frame *);
static bool read_handler(struct intr_frame *);
static bool write_handler(struct intr_frame *);
static bool seek_handler(struct intr_frame *);
static bool tell_handler(struct intr_frame *);
static bool close_handler(struct intr_frame *);

static void syscall_handler(struct intr_frame *);
static void sys_exit(int status);
static bool check_usr_ptr(const void *usr_ptr, unsigned bytes);
static bool check_usr_args(const uint32_t *args, size_t argc);
static bool check_buffer(const void *buffer);
static fd_t allocate_fd(void);
static struct file_entry *get_file_entry(fd_t file_fd);
static SYS_WRAPPER get_handler(int syscall_num);

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

    lock_init(&file_lock);
}

/* System calls handler checks the stack pointer and
   the arguments passed and handles the system call. */
static void
syscall_handler(struct intr_frame *f)
{
    int syscall_num;
    SYS_WRAPPER handler;
    bool success = true;

    /* Checks stack pointer. */
    if (!check_usr_ptr(f->esp, 4))
        sys_exit(-1);

    syscall_num = *((int *)f->esp);

    /* Checks if the system call number in the range. */
    if (syscall_num < 0 || syscall_num >= SYS_CALL_NUM)
        sys_exit(-1);

    /* Gets the desired system call handler. */
    handler = get_handler(syscall_num);
    /* Runs the system call handler. */
    success = handler(f);
    if (!success)
        sys_exit(-1);
}

static SYS_WRAPPER get_handler(int syscall_num)
{
    switch (syscall_num)
    {
    case SYS_HALT:
        return halt_handler;
    case SYS_EXIT:
        return exit_handler;
    case SYS_EXEC:
        return exec_handler;
    case SYS_WAIT:
        return wait_handler;
    case SYS_CREATE:
        return create_handler;
    case SYS_REMOVE:
        return remove_handler;
    case SYS_OPEN:
        return open_handler;
    case SYS_FILESIZE:
        return filesize_handler;
    case SYS_READ:
        return read_handler;
    case SYS_WRITE:
        return write_handler;
    case SYS_SEEK:
        return seek_handler;
    case SYS_TELL:
        return tell_handler;
    case SYS_CLOSE:
        return close_handler;
    }
}

/* Terminates Pintos. */
static void
sys_halt(void)
{
    shutdown_power_off();
    NOT_REACHED();
}

static bool
halt_handler(struct intr_frame *f UNUSED)
{
    sys_halt();

    return true;
}

/* Terminates the current user program and
   returning status to the kernel. */
static void
sys_exit(int status)
{
    /* Saves the exit status and terminates the thread. */
    thread_current()->exit_status = status;
    thread_exit();
}

static bool
exit_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    bool result = true;

    if (!check_usr_args(args, 1))
        return false;

    sys_exit(*(int *)args);

    return true;
}

/* Runs the executable whose name is given in CMDLINE and
   returns the new process’s program id (pid). */
static pid_t
sys_exec(const char *cmdline)
{
    return process_execute(cmdline);
}

static bool
exec_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    if (!check_buffer(*(char **)args))
        return false;

    /* Stores the return value. */
    f->eax = sys_exec(*(char **)args);

    return true;
}

/* Waits for a child process pid and retrieves the
   child’s exit status. */
static int
sys_wait(pid_t pid)
{
    return process_wait(pid);
}

static bool
wait_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    /* Stores the return value. */
    f->eax = sys_wait(*(int *)args);

    return true;
}

/* Creates a new file called file initially initial size bytes
   in size. Returns true if successful, false otherwise. */
static bool
sys_create(const char *file_name, unsigned initial_size)
{
    bool result;

    lock_acquire(&file_lock);
    result = filesys_create(file_name, initial_size);
    lock_release(&file_lock);

    return result;
}

static bool
create_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 2))
        return false;

    if (!check_buffer(*(char **)args))
        return false;

    /* Stores the return value. */
    f->eax = sys_create(*(char **)args, *((unsigned *)(args + 1)));

    return true;
}

/* Deletes the file called file.
   Returns true if successful, false otherwise.*/
static bool
sys_remove(const char *file_name)
{
    bool result;

    lock_acquire(&file_lock);
    result = filesys_remove(file_name);
    lock_release(&file_lock);

    return result;
}

static bool
remove_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    /* Stores the return value. */
    f->eax = sys_remove(*(char **)args);

    return true;
}

/* Opens the file called file. Returns its file descriptor
   or FD_ERROR if the file could not be opened.*/
static int
sys_open(const char *file_name)
{
    struct thread *cur = thread_current();
    struct file *file;
    struct file_entry *f;

    lock_acquire(&file_lock);
    file = filesys_open(file_name);
    lock_release(&file_lock);

    /* Checks if opening file fails. */
    if (file == NULL)
        return FD_ERROR;

    /* Allocates file descriptor entry to pushes into thread OPENED_FILES */
    f = (struct file_entry *)malloc(sizeof(struct file_entry));

    /* Checks if memory allocation fails. */
    if (f == NULL)
    {
        file_close(file);
        return FD_ERROR;
    }

    /* Initialize the entry and pushes it into OPERNED_FILES. */
    f->file = file;
    f->fd = allocate_fd();
    list_push_back(&cur->opened_files, &f->elem);

    return f->fd;
}

static bool
open_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    if (!check_buffer(*(char **)args))
        return false;

    /* Stores the return value. */
    f->eax = sys_open(*(char **)args);

    return true;
}

/* Returns the size, in bytes, of the file open as fd, or -1
   (error value) if the file not found. */
int filesize(int fd)
{
    struct file_entry *f;
    int result;

    /* Gets the file descriptor entry. */
    f = get_file_entry(fd);

    /* Checks if entry not found or its file. */
    if (f == NULL || f->file == NULL)
        return -1;

    lock_acquire(&file_lock);
    result = file_length(f->file);
    lock_release(&file_lock);

    return result;
}

static bool
filesize_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    /* Stores the return value. */
    f->eax = filesize(*(int *)args);

    return true;
}

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read, or -1
   if the file could not be read. */
static int
sys_read(int fd, void *buffer_, unsigned size)
{
    int result;
    uint8_t *buffer = (uint8_t *)buffer_;
    struct file_entry *f;

    /* Can't read from STDOUT. */
    if (fd == STDOUT_FILENO)
        return -1;

    /* Special hanlde for STDIN. */
    if (fd == STDIN_FILENO)
    {
        unsigned i;
        for (i = 0; i < size; i++)
        {
            *(buffer + i) = input_getc();
        }
        return size;
    }

    /* Gets the file desriptor entry. */
    f = get_file_entry(fd);

    /* Checks if entry not found or its file. */
    if (f == NULL || f->file == NULL)
        return -1;

    lock_acquire(&file_lock);
    result = file_read(f->file, buffer, size);
    lock_release(&file_lock);

    return result;
}

static bool
read_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 3))
        return false;

    void *buffer = *(char **)(args + 1);
    uint32_t size = *(args + 2);

    /* Checks if the buffer block valid. */
    if (!check_usr_ptr(buffer, size))
        return false;

    /* Stores the return value. */
    f->eax = sys_read(*(int *)args, buffer, size);

    return true;
}

/* Writes size bytes from buffer to the open file fd.
   Returns the number of bytes actually written, or -1
   (error value) if it is read-only file.*/
static int
sys_write(int fd, void *buffer_, unsigned size)
{
    int result;
    uint8_t *buffer = (uint8_t *)buffer_;
    struct file_entry *f;

    /* Can't write to STDIN. */
    if (fd == STDIN_FILENO)
        return -1;

    /* Special handle for STDOUT. */
    if (fd == STDOUT_FILENO)
    {
        putbuf((char *)buffer, size);
        return (int)size;
    }

    /* Gets the file descriptor entry. */
    f = get_file_entry(fd);

    /* Checks if entry not found or its file. */
    if (f == NULL || f->file == NULL)
        return -1;

    lock_acquire(&file_lock);
    result = file_write(f->file, buffer, size);
    lock_release(&file_lock);

    return result;
}

static bool
write_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 3))
        return false;

    void *buffer = *(char **)(args + 1);
    uint32_t size = *(args + 2);

    /* Checks if the buffer block valid. */
    if (!check_usr_ptr(buffer, size))
        return false;

    /* Stores the return value. */
    f->eax = sys_write(*(int *)args, buffer, size);
    return true;
}

/* Changes the next byte to be read or written in open file fd
   to position. */
static void
sys_seek(int fd, unsigned position)
{
    struct file_entry *f;

    /* Gets the file descriptor entry. */
    f = get_file_entry(fd);

    lock_acquire(&file_lock);
    file_seek(f->file, position);
    lock_release(&file_lock);
}

static bool
seek_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);
    unsigned position;
    int fd;
    struct file_entry *fn;

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 2))
        return false;

    /* Set the position from the second argument. */
    position = *(unsigned *)(args + 1);

    /* Position must be non negative. */
    if ((int)position < 0)
        return false;

    fd = *(int *)args;

    /* Gets the file descriptor entry. */
    fn = get_file_entry(fd);

    /* Checks if entry not found or its file. */
    if (fn == NULL || fn->file == NULL)
        return false;

    sys_seek(fd, position);

    return true;
}

/* Returns the position of the next byte to be read or
   written in open file fd, or -1 if file not found. */
static unsigned
sys_tell(int fd)
{
    struct file_entry *f;
    unsigned result;

    /* Gets the file descriptor entry. */
    f = get_file_entry(fd);

    /* Checks if entry not found or its file. */
    if (f == NULL || f->file == NULL)
        return -1;

    lock_acquire(&file_lock);
    result = file_tell(f->file);
    lock_release(&file_lock);

    return result;
}

static bool
tell_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    /* Stores the return value. */
    f->eax = sys_tell(*(int *)args);

    return true;
}

/* Closes file descriptor fd. */
static void
sys_close(int fd)
{
    /* Gets the file descriptor entry. */
    struct file_entry *f = get_file_entry(fd);

    /* Checks if entry not found. */
    if (f == NULL)
        return;

    fd_close(f);
}

static bool
close_handler(struct intr_frame *f)
{
    uint32_t *args = (uint32_t *)(f->esp + 4);

    /* Checks the arguments passed by the user process. */
    if (!check_usr_args(args, 1))
        return false;

    sys_close(*(int *)args);
    return true;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr)
{
    // if (!is_user_vaddr(uaddr))
    //   return -1;
    if (is_user_vaddr(uaddr))
    {
        return *uaddr;
    }
    return -1;

    // int result;
    // asm("movl $1f, %0; movzbl %1, %0; 1:"
    //     : "=&a"(result)
    //     : "m"(*uaddr));

    // return result;
}

/* Checks the pointer PTR passed by the user process.
   Returns true if valid, or false otherwise. */
static bool
check_usr_ptr(const void *usr_ptr, unsigned bytes)
{
    unsigned i;

    for (i = 0; i < bytes; ++i)
    {
        if (get_user((uint8_t *)usr_ptr + i) == -1)
            return false;
    }

    return true;
}

/* Checks all the arguments ARGS sent by the user process. */
static bool
check_usr_args(const uint32_t *args, size_t argc)
{
    size_t i;

    for (i = 0; i < argc; i++)
    {
        if (!check_usr_ptr(args + i, 4))
            return false;
    }

    return true;
}

/* Checks the buffer block. */
static bool
check_buffer(const void *buffer)
{
    unsigned i = 0;
    int ch = 1;

    while (ch != '\0' && ch != -1)
    {
        ch = -1;
        if (is_user_vaddr((uint8_t *)buffer + i))
        {
            ch = *((uint8_t *)buffer + i);
        }
        // ch = get_user((uint8_t *)buffer + i);
        ++i;
    }

    if (ch == -1)
        return false;

    return true;
}

/* Returns a file descriptor to use for a file. */
static fd_t
allocate_fd(void)
{
    static fd_t next_fd = 2;
    return next_fd++;
}

/* Gets the file descriptor entry whose fd = FILE_FD
   Returns the file_entry, or NULL if not exist.*/
static struct file_entry *
get_file_entry(fd_t file_fd)
{
    struct list_elem *e;

    struct thread *cur = thread_current();

    for (e = list_begin(&cur->opened_files); e != list_end(&cur->opened_files);
         e = list_next(e))
    {
        struct file_entry *f = list_entry(e, struct file_entry, elem);
        if (f->fd == file_fd)
            return f;
    }

    return NULL;
}
