#include "disk_emu.h"
#include <stdint.h>

/* DEFINE CONSTANTS */

#define MAGIC 999
#define FIELD_SIZE 4

/* IN-MEMORY STRUCTURES DEFINITION */

typedef struct {
    int inode;
    int rw_pointer;
} FileDescriptor;

typedef struct {
    int mode;
    int link_cnt;
    int uid;
    int gid;
    int size;
    int data_ptrs[12];
    int indirectPointer;
} iNode;

#define I_NODE_SIZE 72

typedef struct {
    char* name;
    int i_node;
} DirEntry; 

typedef struct {
    DirEntry** entries;
} DirTable;

/* DEFINE GLOBAL VARS CONCERNING FILE SYSTEM STRUCTURE */

int BLOCK_SIZE = 1024;
int I_NODE_TABLE_SIZE = 100;
int ROOT_DIR_INODE = 0; 
int MAX_BLOCK = 1024;
int START_BLOCK_DATA_BLOCKS;
int START_BLOCK_BITMAP;
int START_BYTE_I_NODE_BITMAP;

/* DEFINE GLOBAL VARIABLES RELATED TO IN-MEMORY STRUCTURES */

FileDescriptor* fd_table[100];
int* i_node_table_bitmap; //acts like a cache
iNode** i_node_table; //acts like a cache
DirTable* root_dir; //acts like a cache
uint8_t* free_bitmap; //acts like a cache

// writes data (an integer) to a block, where each entry is a byte. 
// returns 0 on success, -1 if data is too large to fit in block, -2 if ptr is out of bounds
// modifies ptr to point to the next byte in the block
int write_field_to_buf(int data, int* ptr, uint8_t* block[], int size) {
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
    bytes[0] = data & 0xFF;
    bytes[1] = (data >> 8) & 0xFF;
    bytes[2] = (data >> 16) & 0xFF;
    bytes[3] = (data >> 24) & 0xFF;

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
int read_field_from_buf(int* buffer, int* ptr, uint8_t* block[], int size) {
    printf("Reading field from buffer...\n");
    if (*ptr > size) {
        printf("Error: ptr out of bounds\n");
        return -2;
    }

    // read 4 bytes from block
    int bytes[4];
    for (int i = 0; i < 4; i++) {
        bytes[i] = block[*ptr];
        *ptr++;
    }

    // combine bytes into integer
    *buffer = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    printf("Done reading field from buffer\n");
    return 0;
}

// writes i node to i node table (disk and in-memory cache)
int write_to_i_node_table(int i_node_num, iNode* i_node) {
    printf("Writing i-node %d to i-node table...\n", i_node_num);
    //find which block to write to in i node table
    int block_num = i_node_num * sizeof(i_node) / BLOCK_SIZE + 1;
    int block_offset = i_node_num * sizeof(i_node) % BLOCK_SIZE;

    //get block from disk
    uint8_t block[BLOCK_SIZE*2];
    read_blocks(block_num, 2, &block);

    //write i node to block
    int ptr = block_offset;
    write_field_to_buf(i_node->mode, &ptr, &block, BLOCK_SIZE*2);
    write_field_to_buf(i_node->link_cnt, &ptr, &block, BLOCK_SIZE*2);
    write_field_to_buf(i_node->uid, &ptr, &block, BLOCK_SIZE*2);
    write_field_to_buf(i_node->gid, &ptr, &block, BLOCK_SIZE*2);
    write_field_to_buf(i_node->size, &ptr, &block, BLOCK_SIZE*2);
    for (int i = 0; i < 12; i++) {
        write_field_to_buf(i_node->data_ptrs[i], &ptr, &block, BLOCK_SIZE*2);
    }
    write_field_to_buf(i_node->indirectPointer, &ptr, &block, BLOCK_SIZE*2);

    //write block back to disk
    write_blocks(block_num, 2, &block);

    //in-memory cache: write i node to i node table
    i_node_table[i_node_num] = i_node;
    printf("Done writing i-node %d to i-node table\n", i_node_num);
}

// reads i node from i node table (disk and in-memory cache)
void get_from_i_node_table(int i_node_num, iNode* i_node) {
    printf("Getting i-node %d from i-node table...\n", i_node_num);
    //find which block to read from in i node table
    int block_num = i_node_num * sizeof(iNode) / BLOCK_SIZE + 1;
    int block_offset = i_node_num * sizeof(iNode) % BLOCK_SIZE;

    //get block from disk
    uint8_t block[BLOCK_SIZE*2];
    read_blocks(block_num, 2, &block);

    //read i node from block
    int ptr = block_offset;
    read_field_from_buf(&(i_node->mode), &ptr, &block, BLOCK_SIZE*2);
    read_field_from_buf(&(i_node->link_cnt), &ptr, &block, BLOCK_SIZE*2);
    read_field_from_buf(&(i_node->uid), &ptr, &block, BLOCK_SIZE*2);
    read_field_from_buf(&(i_node->gid), &ptr, &block, BLOCK_SIZE*2);
    read_field_from_buf(&(i_node->size), &ptr, &block, BLOCK_SIZE*2);
    for (int i = 0; i < 12; i++) {
        read_field_from_buf(&(i_node->data_ptrs[i]), &ptr, &block, BLOCK_SIZE*2);
    }
    read_field_from_buf(&i_node->indirectPointer, &ptr, &block, BLOCK_SIZE*2);

    //in-memory cache: write i node to i node table
    i_node_table[i_node_num] = i_node;
    printf("Done getting i-node %d from i-node table\n", i_node_num);
}

// reads i node bitmap from disk
void load_inode_bitmap(uint8_t bitmap[]) {
    printf("Loading i-node bitmap from disk...\n");
    uint8_t bitmap_block[BLOCK_SIZE];
    read_blocks(0, 1, &bitmap_block); //super block 
    int start_ptr = START_BYTE_I_NODE_BITMAP;
    read_from_bitmap(bitmap_block, BLOCK_SIZE, start_ptr, bitmap);
    printf("Done loading i-node bitmap from disk\n");
}

// converts bitmap buffer (block buffer) to array of booleans 
void read_from_bitmap(uint8_t* bitmap, int block_size, int start_ptr, uint8_t buf[]) {
    printf("Reading from bitmap...\n");
    int buf_ptr = 0;
    for (int i = 0; i < block_size; i++) {
        for (int j = 0; j < 8; j++) {
            buf[buf_ptr] = (bitmap[start_ptr] & (1 << j)) >> j;
            buf_ptr++;
        }
        start_ptr++;
    }
    printf("Done reading from bitmap\n");
}

// writes to the bitmap buffer
void write_to_bitmap(uint8_t* bitmap, int block_size, int start_ptr, uint8_t buf[]) {
    printf("Writing to bitmap...\n");
    int buf_ptr = 0;
    for (int i = 0; i < block_size; i++) {
        for (int j = 0; j < 8; j++) {
            bitmap[start_ptr] = bitmap[start_ptr] | (buf[buf_ptr] << j);
            buf_ptr++;
        }
        start_ptr++;
    }
    printf("Done writing to bitmap\n");
}

// loads data from blocks into buffer
void load_data_from_blocks(iNode* i_node, uint8_t* buf) {
    printf("Loading data from blocks...\n");
    int num_of_blocks = i_node->size;
    int ptr = 0;
    for (int i = 0; i < num_of_blocks; i++) {
        if (i < 12) {
            read_blocks(i_node->data_ptrs[i], 1, &buf[ptr]);
        } else {
            uint8_t indirect_block[BLOCK_SIZE];
            read_blocks(i_node->indirectPointer, 1, &indirect_block);
            int indirect_ptr = (i - 12) * FIELD_SIZE;
            int data_block_num;
            read_field_from_buf(&data_block_num, &indirect_ptr, &indirect_block, BLOCK_SIZE);
            read_blocks(data_block_num, 1, &buf[ptr]);
        }
        ptr += BLOCK_SIZE;
    }
    printf("Done loading data from blocks\n");
}

void mksfs(int fresh) {
    if (fresh) { // create new file system
        init_fresh_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);
        
        /* STEP 1: CREATE SUPERBLOCK*/

        int ptr = 0;
        uint8_t superblock_buf[BLOCK_SIZE];
        write_field_to_buf(MAGIC, &ptr, &superblock_buf, BLOCK_SIZE);
        write_field_to_buf(BLOCK_SIZE, &ptr, &superblock_buf, BLOCK_SIZE);
        write_field_to_buf(MAX_BLOCK, &ptr, &superblock_buf, BLOCK_SIZE);
        write_field_to_buf(I_NODE_TABLE_SIZE, &ptr, &superblock_buf, BLOCK_SIZE);
        write_field_to_buf(ROOT_DIR_INODE, &ptr, &superblock_buf, BLOCK_SIZE);
        START_BYTE_I_NODE_BITMAP = ptr; //i-node bitmap will be in the superblock
        write_blocks(0, 1, &superblock_buf);

        //set important vars
        START_BLOCK_DATA_BLOCKS = 2 + (I_NODE_TABLE_SIZE * sizeof(iNode) + BLOCK_SIZE - 1) / BLOCK_SIZE;
        int num_of_data_blocks = (BLOCK_SIZE*(MAX_BLOCK - START_BLOCK_DATA_BLOCKS + 1)+1-BLOCK_SIZE)/(BLOCK_SIZE+1);
        START_BLOCK_BITMAP = START_BLOCK_DATA_BLOCKS + num_of_data_blocks;

        /* STEP 2: CREATE ROOT DIR*/

        //create i-node
        i_node_table_bitmap[ROOT_DIR_INODE] = 1; // mark root dir i node as used
        iNode* root_dir_i_node = malloc(sizeof(iNode));
        root_dir_i_node->mode = 0;
        root_dir_i_node->link_cnt = 1; // root dir i node is linked to by root dir
        root_dir_i_node->uid = 0; //index of root dir i node in i node table
        root_dir_i_node->gid = 0;
        root_dir_i_node->size = 0;
        for (int i = 0; i < 12; i++) {
            root_dir_i_node->data_ptrs[i] = 0; // set all data pointers to 0
        }
        root_dir_i_node->indirectPointer = 0;

    } else {
        
        init_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);

        /* STEP 1: BUILD SUPERBLOCK */ 

        //check if magic matches
        uint8_t superblock_buf[BLOCK_SIZE];
        read_blocks(0, 1, &superblock_buf);
        int ptr = 0;
        int magic;
        read_field_from_buf(&magic, &ptr, &superblock_buf, BLOCK_SIZE);
        if (magic != MAGIC) {
            printf("Error: magic number does not match\n");
            return;
        }
        // get block size
        read_field_from_buf(&BLOCK_SIZE, &ptr, &superblock_buf, BLOCK_SIZE);  
        // get i node table size
        read_field_from_buf(&I_NODE_TABLE_SIZE, &ptr, &superblock_buf, BLOCK_SIZE);      
        // get root dir i node
        read_field_from_buf(&ROOT_DIR_INODE, &ptr, &superblock_buf, BLOCK_SIZE);
        // get max block
        read_field_from_buf(&MAX_BLOCK, &ptr, &superblock_buf, BLOCK_SIZE);
        START_BYTE_I_NODE_BITMAP = ptr; //i-node bitmap will be in the superblock
        i_node_table = malloc(I_NODE_TABLE_SIZE * sizeof(uint8_t));
        START_BLOCK_DATA_BLOCKS = 2 + (I_NODE_TABLE_SIZE * sizeof(iNode) + BLOCK_SIZE - 1) / BLOCK_SIZE;
        int num_of_data_blocks = (BLOCK_SIZE*(MAX_BLOCK - START_BLOCK_DATA_BLOCKS + 1)+1-BLOCK_SIZE)/(BLOCK_SIZE+1);
        START_BLOCK_BITMAP = START_BLOCK_DATA_BLOCKS + num_of_data_blocks;


        /* STEP 2: GET I-NODE INFORMATION */

        //load i node bitmap into memory
        i_node_table_bitmap = malloc(I_NODE_TABLE_SIZE * sizeof(uint8_t));
        load_inode_bitmap(i_node_table_bitmap);

        //load i node table into memory
        for (int i = 0; i < I_NODE_TABLE_SIZE; i++) {
            if (i_node_table_bitmap[i]) {
                iNode* i_node = malloc(sizeof(iNode));
                get_from_i_node_table(i, i_node); // i dont care i know this is slow
            }
        }
        

        /* STEP 3: GET ROOT DIR INFORMATION */

        // load root dir into memory
        iNode* root_dir_i_node = i_node_table[ROOT_DIR_INODE];
        uint8_t root_dir_buf[BLOCK_SIZE*root_dir_i_node->size];
        load_data_from_blocks(root_dir_i_node, root_dir_buf);


    }
}

int sfs_getnextfilename(char*) {

}

int sfs_getfilesize(const char*) {

}

int sfs_fopen(char*) {

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