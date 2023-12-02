#include "disk_emu.h"
#include <stdint.h>

/* DEFINE CONSTANTS (constants for disk sizes of structs defined with structs) */

#define MAGIC 999
#define FIELD_SIZE 4
#define UPPER_LIMIT_ARRAY 1024*1024
#define UPPER_LIMIT_FD_TABLE 100
#define MAX_NAME_SIZE 32

/* IN-MEMORY STRUCTURES DEFINITION */

typedef struct {
    int inode;
    int rw_pointer;
    int used;
} FileDescriptor;

typedef struct {
    int mode;
    int link_cnt;
    int uid;
    int size;
    int data_ptrs[12];
    int indirectPointer;
} iNode;
#define I_NODE_SIZE_DISK 68

typedef struct {
    uint8_t used;
    uint8_t name[MAX_NAME_SIZE];
    int i_node;
} DirEntry; 
#define DIR_ENTRY_SIZE_DISK 37 // 32 max name length + 4 bytes for i node + 1 byte for if used or not

typedef struct {
    DirEntry* entries[UPPER_LIMIT_ARRAY];
    int num_of_entries;
} DirTable;

/* DEFINE GLOBAL VARS CONCERNING FILE SYSTEM STRUCTURE */

int BLOCK_SIZE = 4096;
int I_NODE_TABLE_SIZE = 1024;
int ROOT_DIR_INODE_IDX = 0; 
int MAX_BLOCK = 1024;
int START_BLOCK_DATA_BLOCKS;
int START_BLOCK_BITMAP;
int START_BYTE_I_NODE_BITMAP;
int NUM_OF_DATA_BLOCKS;
int NUM_OF_BITMAP_BLOCKS;


/* DEFINE GLOBAL VARIABLES RELATED TO IN-MEMORY STRUCTURES */

FileDescriptor* fd_table[UPPER_LIMIT_FD_TABLE];
uint8_t i_node_table_bitmap[UPPER_LIMIT_ARRAY]; //acts like a cache
iNode* i_node_table[UPPER_LIMIT_ARRAY]; //acts like a cache
DirTable root_dir; //acts like a cache
uint8_t free_bitmap[UPPER_LIMIT_ARRAY]; //acts like a cache

// writes data (an integer) to a block, where each entry is a byte. 
// returns 0 on success, -1 if data is too large to fit in block, -2 if ptr is out of bounds
// modifies ptr to point to the next byte in the block
int write_int_to_buf(int data, int* ptr, uint8_t block[], int size) {
    printf("Writing field to buffer...\n");
    if (*ptr > size) {
        printf("Error: ptr out of bounds\n");
        return -2;
    }

    if (data > 0xFFFFFFFF) {
        printf("Error: data too large to fit in block\n");
        return -1;
    }

    // split data into 4 bytes
    uint8_t bytes[4];
    bytes[0] = (data >> 24) & 0xFF;
    bytes[1] = (data >> 16) & 0xFF;
    bytes[2] = (data >> 8) & 0xFF;
    bytes[3] = data & 0xFF;

    // write bytes to block
    for (int i = 0; i < 4; i++) {
        block[*ptr] = bytes[i];
        *ptr++;
    }

    printf("Done writing field to buffer\n");
    return 0;
}

//reads data (an integer) from a block buffer, where each entry is a byte.
//returns 0 on success, -2 if ptr is out of bounds
//modifies ptr to point to the next byte in the block
int read_int_from_buf(int* buffer, int* ptr, uint8_t block[], int size) {
    printf("Reading field from buffer...\n");
    if (*ptr > size) {
        printf("Error: ptr out of bounds\n");
        return -2;
    }
    
    //read 4 bytes from block
    uint8_t bytes[4];
    for (int i = 0; i < 4; i++) {
        bytes[i] = block[*ptr];
        *ptr++;
    }

    //combine bytes into data
    int data = 0;
    data = data | bytes[0];
    data = data << 8;
    data = data | bytes[1];
    data = data << 8;
    data = data | bytes[2];
    data = data << 8;
    data = data | bytes[3];

    *buffer = data;

    printf("Done reading field from buffer\n");
    return 0;
}

void write_i_node_to_block(int* ptr, int block_num, iNode* i_node) {
    printf("Writing i-node to block...\n");
    uint8_t buf[BLOCK_SIZE*2];
    read_blocks(block_num, 2, buf);
    write_int_to_buf(i_node->mode, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->link_cnt, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->uid, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->size, ptr, buf, BLOCK_SIZE);
    for (int i = 0; i < 12; i++) {
        write_int_to_buf(i_node->data_ptrs[i], ptr, buf, BLOCK_SIZE);
    }
    write_int_to_buf(i_node->indirectPointer, ptr, buf, BLOCK_SIZE);
    write_blocks(block_num, 2, buf);
    printf("Done writing i-node to block\n");
}

//gets the block number and byte pointer to the block where the i-node is stored
void get_i_node_block_coords(int i_node_num, int* block_num, int* ptr) {
    printf("Getting i-node block coords...\n");
    *block_num = (i_node_num * I_NODE_SIZE_DISK) / BLOCK_SIZE + 2;
    *ptr = i_node_num * I_NODE_SIZE_DISK % BLOCK_SIZE;
    printf("Done getting i-node block coords\n");
}

// writes i node to i node table (disk and in-memory cache)
int write_to_i_node_table(iNode* i_node) {

    int i_node_num = i_node->uid;

    printf("Writing i-node %d to i-node table...\n", i_node_num);

    //update in-memory structures 
    i_node_table[i_node_num] = i_node;
    i_node_table_bitmap[i_node_num] = 1;

    //find which block to write to in i node table
    int block_num, ptr;
    get_i_node_block_coords(i_node_num, &block_num, &ptr);

    //write i node to block on disk
    write_i_node_to_block(&ptr, block_num, i_node);

    //update i node bitmap on disk
    uint8_t bitmap_block[BLOCK_SIZE];
    read_blocks(0, 1, bitmap_block); //super block
    int start_ptr = START_BYTE_I_NODE_BITMAP;
    write_to_bitmap_block_buffer(bitmap_block, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr);
    write_blocks(0, 1, bitmap_block);

    printf("Done writing i-node %d to i-node table\n", i_node_num);
    return 0;
}

void read_i_node_from_block(int* ptr, int block_num, iNode* i_node) {
    printf("Reading i-node from block...\n");
    uint8_t buf[BLOCK_SIZE*2];
    read_blocks(block_num, 2, buf);
    read_int_from_buf(&i_node->mode, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->link_cnt, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->uid, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->size, ptr, buf, BLOCK_SIZE);
    for (int i = 0; i < 12; i++) {
        read_int_from_buf(&i_node->data_ptrs[i], ptr, buf, BLOCK_SIZE);
    }
    read_int_from_buf(&i_node->indirectPointer, ptr, buf, BLOCK_SIZE);
    printf("Done reading i-node from block\n");
}

// read from i node table (disk and in-memory cache)
int read_from_i_node_table(int i_node_num, iNode* i_node_container, int from_disk) {
    printf("Reading i-node %d from i-node table...\n", i_node_num);

    //check if i-node is in memory
    if (i_node_table_bitmap[i_node_num] == 0) {
        printf("Error: i-node %d not in memory\n", i_node_num);
        return -1;
    }

    //get i-node
    if (from_disk) {
        //find which block to read from in i node table
        int block_num, ptr;
        get_i_node_block_coords(i_node_num, &block_num, &ptr);

        //read i node from block
        read_i_node_from_block(&ptr, block_num, i_node_container);

        //update in-memory structures
        i_node_table[i_node_num] = i_node_container;

    } else {
        *i_node_container = *i_node_table[i_node_num];
    }

    printf("Done reading i-node %d from i-node table\n", i_node_num);
    return 0;

}

// loads i node bitmap into memory (i_node_table_bitmap)
void load_i_node_bitmap() {
    printf("Loading i-node bitmap from disk...\n");
    //load i-node bitmap block
    uint8_t bitmap_block[BLOCK_SIZE];
    read_blocks(0, 1, bitmap_block); //super block
    int start_ptr = START_BYTE_I_NODE_BITMAP;
    //convert i-node bitmap block to i-node bitmap
    read_from_bitmap_block_buffer(bitmap_block, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr);
    printf("Done loading i-node bitmap from disk\n");
}

// converts bitmap buffer (block buffer) to array of booleans 
void read_from_bitmap_block_buffer(uint8_t bitmap_block_buffer[], uint8_t bitmap_entries[], int num_of_entries, int start_byte) {
    for (int i = 0; i < num_of_entries; i++) {
        int byte_num = i / 8;
        int bit_num = i % 8;
        bitmap_entries[i] = (bitmap_block_buffer[start_byte + byte_num] >> (7-bit_num)) & 1;
    }
}

// writes to the bitmap buffer
void write_to_bitmap_block_buffer(uint8_t bitmap_block_buffer[], uint8_t bitmap_entries[], int num_of_entries, int start_byte) {
    for (int i = 0; i < num_of_entries; i++) {
        int byte_num = i / 8;
        int bit_num = i % 8;
        bitmap_block_buffer[start_byte + byte_num] = bitmap_block_buffer[start_byte + byte_num] | (bitmap_entries[i] << (7-bit_num));
    }
    printf("Done writing to bitmap\n");
}

//get specific data block using i-node
void get_block(iNode* i_node, int block_num, uint8_t buf[]) {
    printf("Getting block %d...\n", block_num);
    if (block_num < 12) {
        //direct pointer
        read_blocks(i_node->data_ptrs[block_num], 1, buf);
    } else {
        //indirect pointer
        uint8_t indirect_block[BLOCK_SIZE];
        read_blocks(i_node->indirectPointer, 1, indirect_block);
        int ptr = (block_num - 12) * FIELD_SIZE;
        int block_num;
        read_int_from_buf(&block_num, &ptr, indirect_block, BLOCK_SIZE);
        read_blocks(block_num, 1, buf);
    }
    printf("Done getting block %d\n", block_num);
}

//save specific data block using i-node
void save_block(iNode* i_node, int block_num, uint8_t buf[]) {
    printf("Saving block %d...\n", block_num);
    if (block_num < 12) {
        //direct pointer
        write_blocks(i_node->data_ptrs[block_num], 1, buf);
    } else {
        //indirect pointer
        uint8_t indirect_block[BLOCK_SIZE];
        read_blocks(i_node->indirectPointer, 1, indirect_block);
        int ptr = (block_num - 12) * FIELD_SIZE;
        int block_num_to_write;
        read_int_from_buf(&block_num_to_write, &ptr, &indirect_block, BLOCK_SIZE);
        write_blocks(block_num_to_write, 1, buf);
    }
    printf("Done saving block %d\n", block_num);
}

// loads data from blocks into buffer
int load_data_from_i_node(iNode* i_node, uint8_t buf[]) {
    printf("Loading data from blocks...\n");

    int num_of_blocks = i_node->size;

    if (num_of_blocks == 0) {
        printf("Nothing to load\n");
        return -1;
    }

    for (int i = 0; i < num_of_blocks; i++) {
        get_block(i_node, i, &buf[i*BLOCK_SIZE]);
    }

    printf("Done loading data from blocks\n");
}

// reserve data block by updating corresponding free bitmap entry
void reserve_data_block(int block_num) {
    printf("Reserving data block %d...\n", block_num);
    //update free bitmap
    free_bitmap[block_num] = 1;
    //update free bitmap on disk
    int buf_size = BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS;
    uint8_t bitmap_block[buf_size]; //buffer
    read_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    int start_ptr = 0;
    write_to_bitmap(bitmap_block, buf_size, start_ptr, free_bitmap);
    write_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    printf("Done reserving data block %d\n", block_num);
}

// find available data block
int find_available_data_block(int* block_num) {
    printf("Finding available data block...\n");
    int found = 0;
    for (int i = 0; i < NUM_OF_DATA_BLOCKS; i++) {
        if (free_bitmap[i] == 0) {
            *block_num = i + START_BLOCK_DATA_BLOCKS;
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("Error: no available data blocks\n");
        return -1;
    }
    printf("Done finding available data block\n");
    return 0;
}

//find available i-node table slot 
int find_available_i_node(int* i_node_num) {
    printf("Finding available i-node...\n");
    int found = 0;
    for (int i = 0; i < I_NODE_TABLE_SIZE; i++) {
        if (i_node_table_bitmap[i] == 0) {
            *i_node_num = i;
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("Error: no available i-nodes\n");
        return -1;
    }
    printf("Done finding available i-node\n");
    return 0;
}

// finds and reserves a data block, and writes number of block to block_num
// and updates the i-node that requires the block
void allocate_data_block(int* block_num) {
    printf("Allocating data block...\n");
    int res = find_available_data_block(block_num);
    if (res == -1) {
        printf("Error: no available data blocks\n");
        return;
    }
    reserve_data_block(*block_num);
    printf("Done allocating data block\n");
}

//writes the superblock of the disk, moves pointer also to next avail byte in block
int write_superblock(int* ptr,int magic,int block_size,int max_block,int i_node_table_size,int root_dir_i_node,int num_of_files) {
    printf("Writing superblock...\n");
    uint8_t buf[block_size];
    write_int_to_buf(magic, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(block_size, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(max_block, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node_table_size, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(root_dir_i_node, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(num_of_files, ptr, buf, BLOCK_SIZE);
    write_blocks(0, 1, buf);
    printf("Done writing superblock\n");
    return 0;
}

//loads the data of the superblock into the buffer
int validate_superblock() {
    printf("Validating superblock...\n");
    uint8_t buffer[BLOCK_SIZE];
    read_blocks(0, 1, buffer);
    int ptr = 0;
    int magic;
    read_int_from_buf(&magic, &ptr, buffer, BLOCK_SIZE);
    if (magic != MAGIC) {
        printf("Error: magic does not match\n");
        return -1;
    }

    printf("Validated superblock\n");
    return 0;
}

//loads i nodes into memory
void load_i_node_table() {
    printf("Loading i-node table...\n");
    for (int i = 0; i < I_NODE_TABLE_SIZE; i++) {
        //if i-node is used
        if (i_node_table_bitmap[i]) {
            read_from_i_node_table(i, i_node_table[i], 1); //this function will refresh the i-node in the cache
        }
    }
    printf("Done loading i-node table\n");
}

//initializes an empty i-node
void init_empty_i_node(iNode* i_node, int id) {
    i_node->mode = 0;
    i_node->link_cnt = 0;
    i_node->uid = id;
    i_node->size = 0;
    for (int i = 0; i < 12; i++) {
        i_node->data_ptrs[i] = 0;
    }
    i_node->indirectPointer = 0;
}

//loads the data of the superblock into the buffer
int load_superblock(int* ptr, int* block_size, int* max_block, int* i_node_table_size, int* root_dir_i_node, int* num_of_files) {
    printf("Loading superblock...\n");
    uint8_t buffer[BLOCK_SIZE];
    read_blocks(0, 1, buffer);
    read_int_from_buf(block_size, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(max_block, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(i_node_table_size, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(root_dir_i_node, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(num_of_files, ptr, buffer, BLOCK_SIZE);
    printf("Done loading superblock\n");
    return 0;
}

//load root directory from data
void load_root_dir(uint8_t data[]) {
    printf("Loading root directory...\n");
    int ptr = 0;
    for (int i = 0; i < root_dir.num_of_entries; i++) {
        //create entry
        DirEntry* entry = malloc(sizeof(DirEntry));
        //read entry from data
        entry->used = data[ptr++];
        for (int j = 0; j < MAX_NAME_SIZE; j++) {
            entry->name[j] = data[ptr];
            ptr++;
        }
        read_int_from_buf(&entry->i_node, &ptr, data, BLOCK_SIZE);
        //add entry to root directory
        root_dir.entries[i] = entry;
    }
    printf("Done loading root directory\n");
}

void mksfs(int fresh) {
    if (fresh) { // create new file system
        init_fresh_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);
        
        /* STEP 1: CREATE SUPERBLOCK*/

        int ptr = 0;
        write_superblock(&ptr,MAGIC,BLOCK_SIZE,MAX_BLOCK,I_NODE_TABLE_SIZE,ROOT_DIR_INODE_IDX,0);
        //set important vars
        START_BYTE_I_NODE_BITMAP = ptr; //i-node bitmap will be in the superblock
        START_BLOCK_DATA_BLOCKS = 2 + (I_NODE_TABLE_SIZE * I_NODE_SIZE_DISK + BLOCK_SIZE - 1) / BLOCK_SIZE;
        NUM_OF_DATA_BLOCKS = (8*(MAX_BLOCK-START_BLOCK_DATA_BLOCKS)*BLOCK_SIZE - 8*BLOCK_SIZE + 1)/(8*BLOCK_SIZE + 1);
        START_BLOCK_BITMAP = START_BLOCK_DATA_BLOCKS + NUM_OF_DATA_BLOCKS;
        NUM_OF_BITMAP_BLOCKS = MAX_BLOCK - START_BLOCK_BITMAP;

        /* STEP 2: CREATE ROOT DIR */ 

        //create i-node
        iNode* root_dir_i_node = malloc(sizeof(iNode));
        init_empty_i_node(root_dir_i_node, ROOT_DIR_INODE_IDX);
        allocate_data_block(&root_dir_i_node->data_ptrs[0]);
        write_to_i_node_table(root_dir_i_node);

    } else {
        
        init_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);

        /* STEP 1: LOAD SUPERBLOCK */ 

        //check if magic matches
        if (validate_superblock() != 0) {
            printf("Error: magic does not match\n");
            return;
        }
        //load superblock into memory
        int ptr = 4;
        load_superblock(&ptr, &BLOCK_SIZE, &MAX_BLOCK, &I_NODE_TABLE_SIZE, &ROOT_DIR_INODE_IDX, &root_dir.num_of_entries);
        // set important vars 
        START_BYTE_I_NODE_BITMAP = ptr; //i-node bitmap will be in the superblock
        START_BLOCK_DATA_BLOCKS = 2 + (I_NODE_TABLE_SIZE * I_NODE_SIZE_DISK + BLOCK_SIZE - 1) / BLOCK_SIZE;
        NUM_OF_DATA_BLOCKS = (8*(MAX_BLOCK-START_BLOCK_DATA_BLOCKS)*BLOCK_SIZE - 8*BLOCK_SIZE + 1)/(8*BLOCK_SIZE + 1);
        START_BLOCK_BITMAP = START_BLOCK_DATA_BLOCKS + NUM_OF_DATA_BLOCKS;
        NUM_OF_BITMAP_BLOCKS = MAX_BLOCK - START_BLOCK_BITMAP;

        /* STEP 2: GET I-NODE INFORMATION */

        load_i_node_bitmap();
        load_i_node_table();

        /* STEP 3: GET ROOT DIR INFORMATION */

        // load root dir into memory
        iNode* root_dir_i_node = i_node_table[ROOT_DIR_INODE_IDX];
        uint8_t root_dir_buf[BLOCK_SIZE*root_dir_i_node->size];
        load_data_from_i_node(root_dir_i_node, root_dir_buf);
        load_root_dir(root_dir_buf);

        /* GET FREE BITMAP INFORMATION */

        // load free bitmap into memory
        uint8_t bitmap_blocks[BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS];
        read_from_bitmap_block_buffer(bitmap_blocks, free_bitmap, NUM_OF_DATA_BLOCKS, 0);

    }
}

// initializes a directory entry with the file name and i_node_num
int init_entry(DirEntry* entry, char* name, int i_node_num) {
    printf("Creating entry...\n");
    entry->used = 1;
    for (int i = 0; i < MAX_NAME_SIZE; i++) {
        entry->name[i] = name[i];
    }
    entry->i_node = i_node_num;
    printf("Done creating entry\n");
}

// writes a directory entry to disk
void write_dir_entry_to_disk(DirEntry* entry, int idx) {
    int block_num = DIR_ENTRY_SIZE_DISK * idx / BLOCK_SIZE;
    int ptr = DIR_ENTRY_SIZE_DISK * idx % BLOCK_SIZE;

    //read buffer from disk 
    uint8_t buffer[BLOCK_SIZE*2];
    get_block(i_node_table[ROOT_DIR_INODE_IDX], block_num, &buffer[0]);
    get_block(i_node_table[ROOT_DIR_INODE_IDX], block_num+1, &buffer[BLOCK_SIZE]);

    //modify buffer
    buffer[ptr++] = entry->used;
    for (int i = 0; i < MAX_NAME_SIZE; i++) {
        buffer[ptr++] = entry->name[i];
    }
    write_int_to_buf(entry->i_node, &ptr, buffer, BLOCK_SIZE);

    //write buffer to disk
    save_block(i_node_table[ROOT_DIR_INODE_IDX], block_num, &buffer[0]);
    save_block(i_node_table[ROOT_DIR_INODE_IDX], block_num+1, &buffer[BLOCK_SIZE]);

}

//creates an entry in the directory table with the file name and i_node_num
int create_new_file(char* name, int* i_node_num) {
    printf("Creating new file...\n");
    
    //create i-node
    int res = find_available_i_node(i_node_num);
    if (res == -1) {
        printf("Error: no available i-nodes\n");
        return -1;
    }
    iNode* new_i_node = malloc(sizeof(iNode));
    init_empty_i_node(new_i_node, *i_node_num);
    
    //create entry in root directory
    DirEntry* entry = malloc(sizeof(DirEntry));
    init_entry(entry, name, *i_node_num);

    int i;
    for (i = 0; i < root_dir.num_of_entries; i++) {
        if (root_dir.entries[i]->used == 0) {
            root_dir.entries[i] = entry;
            break;
        }
    }
    write_dir_entry_to_disk(entry, i);

    //write i-node to i-node table
    write_to_i_node_table(new_i_node);
    printf("Done creating new file\n");
    return 0;
}

int sfs_getnextfilename(char*) {

}

int sfs_getfilesize(const char*) {

}

//checks if file exists in root directory 
int does_file_exist(char* name) {
    for (int i = 0; i < root_dir.num_of_entries; i++) {
        if (strcmp(root_dir.entries[i]->name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

//acts the same way as fopen(), returns a file descriptor
int sfs_fopen(char* name) {
    int i_node_num;

    //check if file exists
    int exists = does_file_exist(name);

    //if file does not exist, create it 
    if (exists) {
        if (create_new_file(name, &i_node_num) != 0) {
            printf("Error: could not create file\n");
            return -1;
        }
    }

    //create file descriptor 
    for (int i = 0; i < UPPER_LIMIT_FD_TABLE; i++) {
        if (fd_table[i]->used == 0) {
            fd_table[i]->inode = i_node_num;
            fd_table[i]->rw_pointer = 0;
            fd_table[i]->used = 1;
            return i;
        }
    }

    printf("Error: no available file descriptors\n");
    return -1;
}

int sfs_fclose(int) {

}

int sfs_fwrite(int, const char*, int) {

}

int sfs_fread(int, char*, int) {

}

int sfs_fseek(int, int) {

}

int sfs_remove(char*) {

}