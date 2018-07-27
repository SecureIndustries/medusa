
struct medusa_buffer {
        void *buffer;
        int64_t length;
        int64_t size;
};

int medusa_buffer_init (struct medusa_buffer *buffer);
void medusa_buffer_uninit (struct medusa_buffer *buffer);
