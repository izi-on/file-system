//TODO proper error codes 

#include "disk_emu.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* DEFINE CONSTANTS (constants for disk sizes of structs defined with structs) */

#define MAGIC 999
#define FIELD_SIZE 4
#define UPPER_LIMIT_ARRAY 1024*1024
#define UPPER_LIMIT_FD_TABLE 100
#define MAX_NAME_SIZE 32 // last byte is for null terminator

/* IN-MEMORY STRUCTURES DEFINITION */

typedef struct {
    unsigned int i_node_num;
    unsigned int rw_pointer; //points to current byte in file
    unsigned int used;
} FileDescriptor;

typedef struct {
    unsigned int mode;
    unsigned int link_cnt;
    unsigned int uid;
    unsigned int size; // implies max file size is 4GB
    unsigned int data_ptrs[12];
    unsigned int indirectPointer;
} iNode;
#define I_NODE_SIZE_DISK 68

typedef struct {
    unsigned char used;
    unsigned char name[MAX_NAME_SIZE];
    unsigned int i_node_num;
} DirEntry; 
#define DIR_ENTRY_SIZE_DISK 37 // 32 max name length + 4 bytes for i node + 1 byte for if used or not

typedef struct {
    DirEntry* entries[UPPER_LIMIT_ARRAY];
    unsigned int num_of_entries;
} DirTable;

/* DEFINE GLOBAL VARS CONCERNING FILE SYSTEM STRUCTURE */

extern unsigned int BLOCK_SIZE;
unsigned int I_NODE_TABLE_SIZE = 1024;
unsigned int ROOT_DIR_INODE_IDX = 0; 
extern unsigned int MAX_BLOCK;
unsigned int START_BLOCK_DATA_BLOCKS;
unsigned int START_BLOCK_BITMAP;
unsigned int START_BYTE_I_NODE_BITMAP;
unsigned int NUM_OF_DATA_BLOCKS;
unsigned int NUM_OF_BITMAP_BLOCKS;


/* DEFINE GLOBAL VARIABLES RELATED TO IN-MEMORY STRUCTURES */

FileDescriptor fd_table[UPPER_LIMIT_FD_TABLE];
unsigned char i_node_table_bitmap[UPPER_LIMIT_ARRAY]; //acts like a cache
iNode* i_node_table[UPPER_LIMIT_ARRAY]; //acts like a cache
DirTable root_dir; //acts like a cache
unsigned char free_bitmap[UPPER_LIMIT_ARRAY]; //acts like a cache

void print_dir() {
    printf("Printing directory...\n");
    for (unsigned int i = 0; i < root_dir.num_of_entries; i++) {
        printf("Entry %d: ", i);
        printf("used: %d ", root_dir.entries[i]->used);
        printf("name: %s ", root_dir.entries[i]->name);
        printf("i_node_num: %d\n", root_dir.entries[i]->i_node_num);
    }
    printf("Printing bitmap...\n");
    for (unsigned int i = 0; i < root_dir.num_of_entries; i++) {
        printf("%d \n", free_bitmap[i]);
    }
    printf("Done printing directory\n");

}

// writes to the bitmap buffer
void write_to_bitmap_block_buffer(unsigned char bitmap_block_buffer[], unsigned char bitmap_entries[], unsigned int num_of_entries, unsigned int start_byte) {
    for (unsigned int i = 0; i < num_of_entries; i++) {
        unsigned int byte_num = i / 8;
        unsigned int bit_num = i % 8;
        bitmap_block_buffer[start_byte + byte_num] = bitmap_block_buffer[start_byte + byte_num] | (bitmap_entries[i] << (7-bit_num));
    }
}

// converts bitmap buffer (block buffer) to array of booleans 
void read_from_bitmap_block_buffer(unsigned char bitmap_block_buffer[], unsigned char bitmap_entries[], unsigned int num_of_entries, unsigned int start_byte) {
    for (unsigned int i = 0; i < num_of_entries; i++) {
        unsigned int byte_num = i / 8;
        unsigned int bit_num = i % 8;
        bitmap_entries[i] = (bitmap_block_buffer[start_byte + byte_num] >> (7-bit_num)) & 1;
    }
}

// writes data (an integer) to a block, where each entry is a byte. 
// returns 0 on success, -1 if data is too large to fit in block, -2 if ptr is out of bounds
// modifies ptr to pounsigned int to the next byte in the block
int write_int_to_buf(unsigned int data, unsigned int* ptr, unsigned char block[], unsigned int size) {
    if (*ptr > size) {
        printf("Error: ptr out of bounds\n");
        return -2;
    }

    if (data > 0xFFFFFFFF) {
        printf("Error: data too large to fit in block\n");
        return -1;
    }

    // split data into 4 bytes
    unsigned char bytes[4];
    bytes[0] = (data >> 24) & 0xFF;
    bytes[1] = (data >> 16) & 0xFF;
    bytes[2] = (data >> 8) & 0xFF;
    bytes[3] = data & 0xFF;

    //write bytes to block
    block[*ptr] = bytes[0]; *ptr = *ptr + 1; 
    block[*ptr] = bytes[1]; *ptr = *ptr + 1;
    block[*ptr] = bytes[2]; *ptr = *ptr + 1;
    block[*ptr] = bytes[3]; *ptr = *ptr + 1;

    return 0;
}

//reads data (an integer) from a block buffer, where each entry is a byte.
//returns 0 on success, -2 if ptr is out of bounds
//modifies ptr to pounsigned int to the next byte in the block
int read_int_from_buf(unsigned int* data, unsigned int* ptr, unsigned char block[], unsigned int size) {
    if (*ptr > size) {
        printf("Error: ptr out of bounds\n");
        return -2;
    }
    
    //read 4 bytes from block
    unsigned char bytes[4];
    for (unsigned int i = 0; i < 4; i++) {
        bytes[i] = block[*ptr];
        *ptr = *ptr + 1;
    }

    //combine bytes into data
    unsigned int res = 0;
    res = res | bytes[0]; res = res << 8;
    res = res | bytes[1]; res = res << 8;
    res = res | bytes[2]; res = res << 8;
    res = res | bytes[3];

    *data = res;

    return 0;
}

//writes i node to disk block
void write_i_node_to_block(unsigned int* ptr, unsigned int block_num, iNode* i_node) {
    unsigned char buf[BLOCK_SIZE*2]; read_blocks(block_num, 2, buf);
    write_int_to_buf(i_node->mode, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->link_cnt, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->uid, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->size, ptr, buf, BLOCK_SIZE);
    for (unsigned int i = 0; i < 12; i++) {
        write_int_to_buf(i_node->data_ptrs[i], ptr, buf, BLOCK_SIZE);
    }
    write_int_to_buf(i_node->indirectPointer, ptr, buf, BLOCK_SIZE);
    write_blocks(block_num, 2, buf);
}

// reads i node from disk block
void read_i_node_from_block(unsigned int* ptr, unsigned int block_num, iNode* i_node) {
    unsigned char buf[BLOCK_SIZE*2]; read_blocks(block_num, 2, buf);
    read_int_from_buf(&i_node->mode, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->link_cnt, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->uid, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->size, ptr, buf, BLOCK_SIZE);
    for (unsigned int i = 0; i < 12; i++) {
        read_int_from_buf(&i_node->data_ptrs[i], ptr, buf, BLOCK_SIZE);
    }
    read_int_from_buf(&i_node->indirectPointer, ptr, buf, BLOCK_SIZE);
}

//gets the block number and byte pointer to the block where the i-node is stored
void get_i_node_block_coords(unsigned int i_node_num, unsigned int* block_num, unsigned int* ptr) {
    *block_num = (i_node_num * I_NODE_SIZE_DISK) / BLOCK_SIZE + 2;
    *ptr = i_node_num * I_NODE_SIZE_DISK % BLOCK_SIZE;
}

//gets the block number and byte pointer to the block where the data is stored
void get_block_coords_from_rw_ptr(unsigned int rw_pointer, unsigned int* block_num, unsigned int* ptr) {
    *block_num = rw_pointer / BLOCK_SIZE;
    *ptr = rw_pointer % BLOCK_SIZE;
}

//calculate the number of blocks needed to store data, starting from ptr
void calculate_num_of_blocks(unsigned int ptr, unsigned int length, unsigned int* num_of_blocks) {
    *num_of_blocks = (ptr + length + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

// writes i node to i node table (disk and in-memory cache)
int write_to_i_node_table(iNode* i_node) {

    unsigned int i_node_num = i_node->uid;

    printf("Writing i-node %d to i-node table...\n", i_node_num);

    //update in-memory structures 
    i_node_table[i_node_num] = i_node;
    i_node_table_bitmap[i_node_num] = 1;

    //find which block to write to in i node table
    unsigned int block_num, ptr; get_i_node_block_coords(i_node_num, &block_num, &ptr);

    //write i node to block on disk
    write_i_node_to_block(&ptr, block_num, i_node);

    //update i node bitmap on disk
    unsigned char bitmap_block[BLOCK_SIZE]; read_blocks(0, 1, bitmap_block); //super block
    unsigned int start_ptr = START_BYTE_I_NODE_BITMAP;
    write_to_bitmap_block_buffer(bitmap_block, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr);
    write_blocks(0, 1, bitmap_block);

    printf("Done writing i-node %d to i-node table\n", i_node_num);
    return 0;
}


// read from i node table (disk and in-memory cache)
int read_from_i_node_table(unsigned int i_node_num, iNode** i_node_container, unsigned int from_disk) {
    printf("Reading i-node %d from i-node table...\n", i_node_num);

    //check if i-node is in memory
    if (i_node_table_bitmap[i_node_num] == 0) {
        printf("Error: i-node %d not in memory\n", i_node_num);
        return -1;
    }

    //get i-node
    if (from_disk) {
        //find which block to read from in i node table
        unsigned int block_num, ptr; get_i_node_block_coords(i_node_num, &block_num, &ptr);

        //read i node from block
        read_i_node_from_block(&ptr, block_num, *i_node_container);

        //update in-memory structures
        i_node_table[i_node_num] = *i_node_container;

    } else {
        *i_node_container = i_node_table[i_node_num];
    }

    printf("Done reading i-node %d from i-node table\n", i_node_num);
    return 0;

}

// loads i node bitmap into memory (i_node_table_bitmap)
void load_i_node_bitmap() {
    printf("Loading i-node bitmap from disk...\n");
    //load i-node bitmap block
    unsigned char bitmap_block[BLOCK_SIZE]; read_blocks(0, 1, bitmap_block); //super block
    unsigned int start_ptr = START_BYTE_I_NODE_BITMAP;
    //convert i-node bitmap block to i-node bitmap
    read_from_bitmap_block_buffer(bitmap_block, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr);
    printf("Done loading i-node bitmap from disk\n");
}


//get specific data block using i-node
int get_block(iNode* i_node, unsigned int block_num, unsigned char buf[]) {
    printf("Getting block %d...\n", block_num);

    unsigned int num_of_blocks_for_i_node = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (block_num > num_of_blocks_for_i_node) {
        printf("Error: block number out of bounds\n");
        return -1;
    }

    if (block_num < 12) {
        //direct pointer
        read_blocks(i_node->data_ptrs[block_num], 1, buf);
    } else {
        //indirect pointer
        unsigned char indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
        unsigned int ptr = (block_num - 12) * FIELD_SIZE;
        unsigned int block_to_read; read_int_from_buf(&block_to_read, &ptr, indirect_block, BLOCK_SIZE);
        read_blocks(block_to_read, 1, buf);
    }
    printf("Done getting block %d\n", block_num);
    return 0;
}

//get specified amount of blocks from i-node until 
void get_blocks(iNode* i_node, unsigned int start_block_num, unsigned int num_of_blocks, unsigned char buf[]) {
    printf("Getting blocks...\n");
    for (unsigned int i = 0; i < num_of_blocks; i++) {
        if (get_block(i_node, start_block_num + i, &buf[i*BLOCK_SIZE]) == -1) {
            return;
        }
    }
    printf("Done getting blocks\n");
}

// TODO abstract the block num checking function (<12 or indirect)
// marks the index-th slot with the data block number in-memory and on disk
unsigned int mark_data_block_on_i_node(iNode* i_node, unsigned int data_block_num, unsigned int index) {  
    printf("Marking data block %d on i-node...\n", data_block_num);
    if (index < 12) {
        //direct pointer
        i_node->data_ptrs[index] = data_block_num;
        write_to_i_node_table(i_node);
    } else if (index < 12 + BLOCK_SIZE / FIELD_SIZE) {
        //indirect pointer
        unsigned char indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
        unsigned int ptr = (index - 12) * FIELD_SIZE;
        write_int_to_buf(data_block_num, &ptr, indirect_block, BLOCK_SIZE);
        write_blocks(i_node->indirectPointer, 1, indirect_block);        
    } else {
        printf("Error: block number out of bounds\n");
        return -1;
    }
    printf("Done marking data block %d on i-node\n", data_block_num);
    return 0;
}

// find available data block
int find_available_data_block(unsigned int* block_num) {
    printf("Finding available data block...\n");
    print_dir();
    unsigned int found = 0;
    for (unsigned int i = 0; i < NUM_OF_DATA_BLOCKS; i++) {
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
    printf("Done finding available data block, found %d\n", *block_num);
    return 0;
}

// reserve data block by updating corresponding free bitmap entry
void reserve_data_block(unsigned int block_num) {
    printf("Reserving data block %d...\n", block_num);
    //update free bitmap
    free_bitmap[block_num - START_BLOCK_DATA_BLOCKS] = 1;
    //update free bitmap on disk
    unsigned int buf_size = BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS;
    unsigned char bitmap_block[buf_size]; read_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    unsigned int start_ptr = 0;
    write_to_bitmap_block_buffer(bitmap_block, free_bitmap, NUM_OF_DATA_BLOCKS, start_ptr);
    write_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    printf("Done reserving data block %d\n", block_num);
}

// finds and reserves a data block, and writes number of block to block_num
void allocate_data_block(unsigned int* block_num) {
    printf("Allocating data block...\n");
    unsigned int res = find_available_data_block(block_num);
    if (res == -1) {
        printf("Error: no available data blocks\n");
        return;
    }
    reserve_data_block(*block_num);
    printf("Done allocating data block\n");
}

//save specific data block using i-node
int save_block(iNode* i_node, unsigned int block_num, unsigned char buf[]) {
    printf("Saving block %d...\n", block_num);
    
    unsigned int num_of_blocks_for_i_node = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (block_num > num_of_blocks_for_i_node) {
        printf("Error: block number out of bounds\n");
        return -1;
    }

    if (block_num < 12) {
        //direct pointer
        write_blocks(i_node->data_ptrs[block_num], 1, buf);
    } else if (block_num < 12 + BLOCK_SIZE / FIELD_SIZE) {
        //indirect pointer
        unsigned char indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
        unsigned int ptr = (block_num - 12) * FIELD_SIZE;
        unsigned int block_num_to_write; read_int_from_buf(&block_num_to_write, &ptr, indirect_block, BLOCK_SIZE);
        write_blocks(block_num_to_write, 1, buf);
    } else {
        printf("Error: block number out of bounds\n");
        return -1;
    }
    printf("Done saving block %d\n", block_num);
    return 0;
}

//save specified amount of blocks from i-node
void save_blocks(iNode* i_node, unsigned int start_block_num, unsigned int num_of_blocks, unsigned char buf[]) {
    printf("Saving blocks...\n");
    for (unsigned int i = 0; i < num_of_blocks; i++) {
        save_block(i_node, start_block_num + i, &buf[i*BLOCK_SIZE]);
    }
    printf("Done saving blocks\n");
}

// loads data from blocks into buffer
int load_data_from_i_node(iNode* i_node, unsigned char buf[]) {
    printf("Loading data from blocks...\n");

    unsigned int num_of_blocks = i_node->size + BLOCK_SIZE - 1 / BLOCK_SIZE;

    if (num_of_blocks == 0) {
        printf("Nothing to load\n");
        return -1;
    }

    for (unsigned int i = 0; i < num_of_blocks; i++) {
        get_block(i_node, i, &buf[i*BLOCK_SIZE]);
    }

    printf("Done loading data from blocks\n");
    return 0;
}

//find available i-node table slot 
int find_available_i_node(unsigned int* i_node_num) {
    printf("Finding available i-node...\n");
    unsigned int found = 0;
    for (unsigned int i = 0; i < I_NODE_TABLE_SIZE; i++) {
        if (i_node_table_bitmap[i] == 0) {
            printf("Found available i-node %d\n", i);
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



//writes the superblock of the disk, moves pointer also to next avail byte in block
int write_superblock(unsigned int* ptr,unsigned int magic,unsigned int block_size,unsigned int max_block,unsigned int i_node_table_size,unsigned int root_dir_i_node,unsigned int num_of_files) {
    printf("Writing superblock...\n");
    unsigned char buf[block_size];
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
    unsigned char buffer[BLOCK_SIZE]; read_blocks(0, 1, buffer);
    unsigned int ptr = 0;
    unsigned int magic; read_int_from_buf(&magic, &ptr, buffer, BLOCK_SIZE);
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
    for (unsigned int i = 0; i < I_NODE_TABLE_SIZE; i++) {
        //if i-node is used
        if (i_node_table_bitmap[i]) {
            read_from_i_node_table(i, &i_node_table[i], 1); //this function will refresh the i-node in the cache
        }
    }
    printf("Done loading i-node table\n");
}

//initializes an empty i-node
void init_empty_i_node(iNode* i_node, unsigned int id) {
    i_node->mode = 0;
    i_node->link_cnt = 0;
    i_node->uid = id;
    i_node->size = 0;
    for (unsigned int i = 0; i < 12; i++) {
        i_node->data_ptrs[i] = 0;
    }
    i_node->indirectPointer = 0;
    i_node_table_bitmap[id] = 1;
}

//loads the data of the superblock into the buffer
int load_superblock(unsigned int* ptr, unsigned int* block_size, unsigned int* max_block, unsigned int* i_node_table_size, unsigned int* root_dir_i_node, unsigned int* num_of_files) {
    printf("Loading superblock...\n");
    unsigned char buffer[BLOCK_SIZE]; read_blocks(0, 1, buffer);
    read_int_from_buf(block_size, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(max_block, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(i_node_table_size, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(root_dir_i_node, ptr, buffer, BLOCK_SIZE);
    read_int_from_buf(num_of_files, ptr, buffer, BLOCK_SIZE);
    printf("Done loading superblock\n");
    return 0;
}

//load root directory from data
void load_root_dir(unsigned char data[]) {
    printf("Loading root directory...\n");
    unsigned int ptr = 0;
    for (unsigned int i = 0; i < root_dir.num_of_entries; i++) {
        //create entry
        DirEntry* entry = malloc(sizeof(DirEntry));
        //read entry from data
        entry->used = data[ptr++];
        for (unsigned int j = 0; j < MAX_NAME_SIZE; j++) {
            entry->name[j] = data[ptr];
            ptr++;
        }
        read_int_from_buf(&entry->i_node_num, &ptr, data, BLOCK_SIZE);
        //add entry to root directory
        root_dir.entries[i] = entry;
    }
    printf("Done loading root directory\n");
}

void mksfs(unsigned int fresh) {
    if (fresh) { // create new file system
        init_fresh_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);
        
        /* STEP 1: CREATE SUPERBLOCK*/

        printf("CREATING SUPERBLOCK\n");
        unsigned int ptr = 0;
        write_superblock(&ptr,MAGIC,BLOCK_SIZE,MAX_BLOCK,I_NODE_TABLE_SIZE,ROOT_DIR_INODE_IDX,0);
        //set important vars
        START_BYTE_I_NODE_BITMAP = ptr; //i-node bitmap will be in the superblock
        START_BLOCK_DATA_BLOCKS = 2 + (I_NODE_TABLE_SIZE * I_NODE_SIZE_DISK + BLOCK_SIZE - 1) / BLOCK_SIZE;
        NUM_OF_DATA_BLOCKS = (8*(MAX_BLOCK-START_BLOCK_DATA_BLOCKS)*BLOCK_SIZE - 8*BLOCK_SIZE + 1)/(8*BLOCK_SIZE + 1);
        START_BLOCK_BITMAP = START_BLOCK_DATA_BLOCKS + NUM_OF_DATA_BLOCKS;
        NUM_OF_BITMAP_BLOCKS = MAX_BLOCK - START_BLOCK_BITMAP;
        printf("DONE CREATING SUPERBLOCK\n");

        /* STEP 2: CREATE ROOT DIR */ 

        printf("CREATING ROOT DIR\n");
        //create i-node
        iNode* root_dir_i_node = malloc(sizeof(iNode));
        init_empty_i_node(root_dir_i_node, ROOT_DIR_INODE_IDX);
        allocate_data_block(&root_dir_i_node->data_ptrs[0]);
        write_to_i_node_table(root_dir_i_node);
        printf("DONE CREATING ROOT DIR\n");

    } else {
        
        init_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);

        /* STEP 1: LOAD SUPERBLOCK */ 

        //check if magic matches
        if (validate_superblock() != 0) {
            printf("Error: magic does not match\n");
            return;
        }
        //load superblock into memory
        unsigned int ptr = 4;
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
        iNode* root_dir_i_node; read_from_i_node_table(ROOT_DIR_INODE_IDX, &root_dir_i_node, 0); 
        unsigned char root_dir_buf[BLOCK_SIZE + root_dir_i_node->size]; load_data_from_i_node(root_dir_i_node, root_dir_buf);
        load_root_dir(root_dir_buf);

        /* GET FREE BITMAP INFORMATION */

        // load free bitmap into memory
        unsigned char bitmap_block_buffer[BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS]; read_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block_buffer);
        read_from_bitmap_block_buffer(bitmap_block_buffer, free_bitmap, NUM_OF_DATA_BLOCKS, 0);

    }
}

// initializes a directory entry with the file name and i_node_num
void init_entry(DirEntry* entry, char* name, unsigned int i_node_num) {
    printf("Creating entry...\n");
    entry->used = 1;
    for (unsigned int i = 0; i < MAX_NAME_SIZE; i++) {
        entry->name[i] = name[i];
    }
    entry->i_node_num = i_node_num;
    printf("Done creating entry\n");
}

void print_i_node(iNode* i_node) {
    printf("Printing i-node...\n");
    printf("mode: %d\n", i_node->mode);
    printf("link_cnt: %d\n", i_node->link_cnt);
    printf("uid: %d\n", i_node->uid);
    printf("size: %d\n", i_node->size);
    printf("data_ptrs: ");
    for (unsigned int i = 0; i < 12; i++) {
        printf("%d ", i_node->data_ptrs[i]);
    }
    printf("\n");
    printf("indirectPointer: %d\n", i_node->indirectPointer);
    printf("Done printing i-node\n");
}

//TODO handle dir expansion

// writes a directory entry to disk
void write_dir_entry_to_disk(DirEntry* entry, unsigned int idx) {
    printf("Writing directory entry to disk...\n");
    unsigned int block_num = DIR_ENTRY_SIZE_DISK * idx / BLOCK_SIZE;
    unsigned int ptr = DIR_ENTRY_SIZE_DISK * idx % BLOCK_SIZE;

    //read buffer from disk 
    unsigned char buffer[BLOCK_SIZE*2];
    get_block(i_node_table[ROOT_DIR_INODE_IDX], block_num, &buffer[0]);
    get_block(i_node_table[ROOT_DIR_INODE_IDX], block_num+1, &buffer[BLOCK_SIZE]);

    //modify buffer
    buffer[ptr++] = entry->used;
    for (unsigned int i = 0; i < MAX_NAME_SIZE; i++) {
        buffer[ptr++] = entry->name[i];
    }
    write_int_to_buf(entry->i_node_num, &ptr, buffer, BLOCK_SIZE);

    //write buffer to disk
    save_block(i_node_table[ROOT_DIR_INODE_IDX], block_num, &buffer[0]);
    save_block(i_node_table[ROOT_DIR_INODE_IDX], block_num+1, &buffer[BLOCK_SIZE]);
    printf("Done writing directory entry to disk\n");
}

//expands i-node to desired new length
int expand_i_node(iNode* i_node, unsigned int num_of_bytes) {
    printf("Expanding i-node...\n");

    // get number of data blocks currently reserved for i-node
    unsigned int num_of_blocks_i_node = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    //check if we need new data blocks
    unsigned int num_of_blocks = ((i_node->size-1) % BLOCK_SIZE + num_of_bytes) / BLOCK_SIZE;
    for (unsigned int i = 0; i < num_of_blocks; i++) {
        unsigned int block_num; allocate_data_block(&block_num);
        int res = mark_data_block_on_i_node(i_node, block_num, num_of_blocks_i_node + i);
        printf("%d\n", res);
        if (res != 0) {
            printf("Error: could not mark data block on i-node\n");
            return -1;
        };
    }

    //update i-node size
    i_node->size += num_of_bytes;
    write_to_i_node_table(i_node);

    printf("Done expanding i-node\n");
    return 0;
}


// TODO handle dir expansion
//creates an entry in the directory table with the file name and i_node_num
int create_new_file(char* name, unsigned int* i_node_num) {
    printf("Creating new file...\n");
    
    //create i-node
    unsigned int res = find_available_i_node(i_node_num);
    if (res != 0) {
        printf("Error: no available i-nodes\n");
        return res;
    }
    iNode* new_i_node = malloc(sizeof(iNode));
    init_empty_i_node(new_i_node, *i_node_num);
    
    //create entry in root directory
    DirEntry* entry = malloc(sizeof(DirEntry));
    init_entry(entry, name, *i_node_num);

    unsigned int i;
    for (i = 0; i < root_dir.num_of_entries; i++) {
        if (root_dir.entries[i]->used == 0) {
            root_dir.entries[i] = entry;
            break;
        }
    }
    if (i == root_dir.num_of_entries) {
        if (root_dir.num_of_entries == UPPER_LIMIT_ARRAY) {
            printf("Error: root directory full\n");
            return -2;
        }
        root_dir.entries[i] = entry;
        root_dir.num_of_entries++;
    }
    write_dir_entry_to_disk(entry, i);

    //write i-node to i-node table
    write_to_i_node_table(new_i_node);
    printf("Done creating new file\n");
    return 0;
}

// TODO implement 
// int sfs_getnextfilename(char*) {
//     printf("Getting next file name...\n");

//     printf("Done getting next file name\n");
//     return 0;
// }

//checks if file exists in root directory, if it does also get the i-node number
int does_file_exist(char* name, unsigned int* i_node_num) {
    for (unsigned int i = 0; i < root_dir.num_of_entries; i++) {
        if (strcmp(root_dir.entries[i]->name, name) == 0) {
            *i_node_num = root_dir.entries[i]->i_node_num;
            return 1;
        }
    }
    return 0;
}

//acts the same way as fopen(), returns a file descriptor
int sfs_fopen(char* name) {

    printf("OPENING FILE...\n");
    //check length of name
    unsigned int name_len = strlen(name);
    if (name_len >= MAX_NAME_SIZE) {
        printf("Error: name too long\n");
        return -1;
    }

    unsigned int i_node_num;

    //check if file exists
    unsigned int exists = does_file_exist(name, &i_node_num);

    //if file does not exist, create it 
    if (!exists) {
        if (create_new_file(name, &i_node_num) != 0) {
            printf("Error: could not create file\n");
            return -1;
        }
        //create file descriptor 
        for (unsigned int i = 0; i < UPPER_LIMIT_FD_TABLE; i++) {
            if (fd_table[i].used == 0) {
                fd_table[i].i_node_num = i_node_num;
                fd_table[i].rw_pointer = 0;
                fd_table[i].used = 1;
                printf("DONE OPENING FILE\n");
                return i;
            }
        }
        printf("Error: no available file descriptors\n");
        return -1;
    } else {
        //find corresponding file descriptor
        for (unsigned int i = 0; i < UPPER_LIMIT_FD_TABLE; i++) {
            if (fd_table[i].used == 1 && fd_table[i].i_node_num == i_node_num) {
                printf("DONE OPENING FILE\n");
                return i;
            }
        }
        printf("Could not find file descriptor, but found file name\n");
        return -1;
    }
}


int sfs_fclose(int fd) {
    printf("Closing file...\n");

    if (fd_table[fd].used == 0) {
        printf("Error: file descriptor not in use\n");
        return -1;
    }

    fd_table[fd].used = 0;
    printf("Done closing file\n");
    return 0;
}

int sfs_getfilesize(char* name) {
    printf("Getting file size...\n");

    int fd = sfs_fopen(name);
    if (fd == -1) {
        printf("Error: could not open file\n");
        return -1;
    }

    FileDescriptor file_descriptor = fd_table[fd];
    iNode* i_node; read_from_i_node_table(file_descriptor.i_node_num, &i_node, 0);    
    sfs_fclose(fd);

    printf("Done getting file size\n");
    return i_node->size;
}

int sfs_fwrite(int fd, char* buf, int length) {
    printf("WRITING TO FILE...\n");

    FileDescriptor file_descriptor = fd_table[fd];

    iNode* i_node; read_from_i_node_table(file_descriptor.i_node_num, &i_node, 0);

    unsigned int rw_pointer = file_descriptor.rw_pointer;

    //check if we need to expand i-node size
    if (rw_pointer + length >= i_node->size) {
        if (expand_i_node(i_node, rw_pointer + length - i_node->size + 1) != 0) {
            printf("Error: could not expand i-node\n");
            return -1;
        }
    }

    unsigned int block_num, ptr, num_of_blocks;
    get_block_coords_from_rw_ptr(rw_pointer, &block_num, &ptr);
    calculate_num_of_blocks(ptr, length, &num_of_blocks);

    //populate buffer with the data with the blocks we will be changing
    unsigned char data_buf[BLOCK_SIZE*num_of_blocks];
    get_blocks(i_node, block_num, num_of_blocks, data_buf);

    //write data to buffer
    for (unsigned int i = 0; i < length; i++) {
        data_buf[ptr++] = buf[i];
    }

    //save buffer to disk
    save_blocks(i_node, block_num, num_of_blocks, data_buf);

    //update file descriptor
    file_descriptor.rw_pointer += length;

    printf("DONE WRITING TO FILE\n");
    return 0;
}

int sfs_fread(int fd, char* buf, int length) {
    printf("Reading from file...\n");

    FileDescriptor file_descriptor = fd_table[fd];
    iNode* i_node; read_from_i_node_table(file_descriptor.i_node_num, &i_node, 0);

    unsigned int rw_pointer = file_descriptor.rw_pointer;
    unsigned int block_num, ptr, num_of_blocks;

    get_block_coords_from_rw_ptr(rw_pointer, &block_num, &ptr);
    calculate_num_of_blocks(ptr, length, &num_of_blocks);

    //intermediate buffer to store data from disk
    unsigned char data_buf[BLOCK_SIZE*num_of_blocks];
    get_blocks(i_node, block_num, num_of_blocks, data_buf);

    //store data in buffer
    for (unsigned int i = 0; i < length; i++) {
        buf[i] = data_buf[ptr++];
    }

    printf("Done reading from file\n");
    return 0;
}

int sfs_fseek(int fd, int offset) {
    printf("Seeking file...\n");

    FileDescriptor file_descriptor = fd_table[fd];
    file_descriptor.rw_pointer = offset;

    printf("Done seeking file\n");
    return 0;
}

int sfs_remove(char* name) {
    printf("Removing file...\n");
    // step 1: find file in root directory
    unsigned int i_node_num;
    unsigned int found = does_file_exist(name, &i_node_num);
    if (!found) {
        printf("Error: file does not exist\n");
        return -1;
    }

    // step 2: remove entry from root directory
    for (unsigned int i = 0; i < root_dir.num_of_entries; i++) {
        if (strcmp(root_dir.entries[i]->name, name) == 0) {
            root_dir.entries[i]->used = 0;
            write_dir_entry_to_disk(root_dir.entries[i], i);
            break;
        }
    }

    //step 3: mark all data blocks as free
    iNode* i_node; read_from_i_node_table(i_node_num, &i_node, 0);
    unsigned int num_of_blocks = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (unsigned int i = 0; i < num_of_blocks; i++) {
        if (i < 12) {
            //direct pointer
            free_bitmap[i_node->data_ptrs[i]] = 0;
        } else {
            //indirect pointer
            unsigned char indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
            unsigned int ptr = (i - 12) * FIELD_SIZE;
            unsigned int block_num; read_int_from_buf(&block_num, &ptr, indirect_block, BLOCK_SIZE);
            free_bitmap[block_num] = 0;
        }
    }
    //update free bitmap on disk
    unsigned int buf_size = BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS;
    unsigned char bitmap_block[buf_size]; read_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    unsigned int start_ptr = 0;
    write_to_bitmap_block_buffer(bitmap_block, free_bitmap, NUM_OF_DATA_BLOCKS, start_ptr);
    write_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);

    //step 4: mark i-node as free
    i_node_table_bitmap[i_node_num] = 0;
    //update i node bitmap on disk
    unsigned char bitmap_block2[BLOCK_SIZE]; read_blocks(0, 1, bitmap_block2); //super block
    unsigned int start_ptr2 = START_BYTE_I_NODE_BITMAP;
    write_to_bitmap_block_buffer(bitmap_block2, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr2);
    write_blocks(0, 1, bitmap_block2);

    printf("Done removing file\n");
    return 0;
}