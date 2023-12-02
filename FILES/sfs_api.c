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
    u_int32_t i_node_num;
    u_int32_t rw_pointer; //points to current byte in file
    u_int32_t used;
} FileDescriptor;

typedef struct {
    u_int32_t mode;
    u_int32_t link_cnt;
    u_int32_t uid;
    u_int32_t size; // implies max file size is 4GB
    u_int32_t data_ptrs[12];
    u_int32_t indirectPointer;
} iNode;
#define I_NODE_SIZE_DISK 68

typedef struct {
    uint8_t used;
    uint8_t name[MAX_NAME_SIZE];
    u_int32_t i_node_num;
} DirEntry; 
#define DIR_ENTRY_SIZE_DISK 37 // 32 max name length + 4 bytes for i node + 1 byte for if used or not

typedef struct {
    DirEntry* entries[UPPER_LIMIT_ARRAY];
    u_int32_t num_of_entries;
} DirTable;

/* DEFINE GLOBAL VARS CONCERNING FILE SYSTEM STRUCTURE */

u_int32_t BLOCK_SIZE = 4096;
u_int32_t I_NODE_TABLE_SIZE = 1024;
u_int32_t ROOT_DIR_INODE_IDX = 0; 
u_int32_t MAX_BLOCK = 1024;
u_int32_t START_BLOCK_DATA_BLOCKS;
u_int32_t START_BLOCK_BITMAP;
u_int32_t START_BYTE_I_NODE_BITMAP;
u_int32_t NUM_OF_DATA_BLOCKS;
u_int32_t NUM_OF_BITMAP_BLOCKS;


/* DEFINE GLOBAL VARIABLES RELATED TO IN-MEMORY STRUCTURES */

FileDescriptor fd_table[UPPER_LIMIT_FD_TABLE];
uint8_t i_node_table_bitmap[UPPER_LIMIT_ARRAY]; //acts like a cache
iNode* i_node_table[UPPER_LIMIT_ARRAY]; //acts like a cache
DirTable root_dir; //acts like a cache
uint8_t free_bitmap[UPPER_LIMIT_ARRAY]; //acts like a cache



// writes to the bitmap buffer
void write_to_bitmap_block_buffer(uint8_t bitmap_block_buffer[], uint8_t bitmap_entries[], u_int32_t num_of_entries, u_int32_t start_byte) {
    for (u_int32_t i = 0; i < num_of_entries; i++) {
        u_int32_t byte_num = i / 8;
        u_int32_t bit_num = i % 8;
        bitmap_block_buffer[start_byte + byte_num] = bitmap_block_buffer[start_byte + byte_num] | (bitmap_entries[i] << (7-bit_num));
    }
}

// converts bitmap buffer (block buffer) to array of booleans 
void read_from_bitmap_block_buffer(uint8_t bitmap_block_buffer[], uint8_t bitmap_entries[], u_int32_t num_of_entries, u_int32_t start_byte) {
    for (u_int32_t i = 0; i < num_of_entries; i++) {
        u_int32_t byte_num = i / 8;
        u_int32_t bit_num = i % 8;
        bitmap_entries[i] = (bitmap_block_buffer[start_byte + byte_num] >> (7-bit_num)) & 1;
    }
}

// writes data (an integer) to a block, where each entry is a byte. 
// returns 0 on success, -1 if data is too large to fit in block, -2 if ptr is out of bounds
// modifies ptr to pou_int32_t to the next byte in the block
u_int32_t write_int_to_buf(u_int32_t data, u_int32_t* ptr, uint8_t block[], u_int32_t size) {
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

    //write bytes to block
    block[*ptr] = bytes[0]; *ptr = *ptr + 1; 
    block[*ptr] = bytes[1]; *ptr = *ptr + 1;
    block[*ptr] = bytes[2]; *ptr = *ptr + 1;
    block[*ptr] = bytes[3]; *ptr = *ptr + 1;

    return 0;
}

//reads data (an integer) from a block buffer, where each entry is a byte.
//returns 0 on success, -2 if ptr is out of bounds
//modifies ptr to pou_int32_t to the next byte in the block
u_int32_t read_int_from_buf(u_int32_t* data, u_int32_t* ptr, uint8_t block[], u_int32_t size) {
    if (*ptr > size) {
        printf("Error: ptr out of bounds\n");
        return -2;
    }
    
    //read 4 bytes from block
    uint8_t bytes[4];
    for (u_int32_t i = 0; i < 4; i++) {
        bytes[i] = block[*ptr];
        *ptr = *ptr + 1;
    }

    //combine bytes into data
    u_int32_t res = 0;
    res = res | bytes[0]; res = res << 8;
    res = res | bytes[1]; res = res << 8;
    res = res | bytes[2]; res = res << 8;
    res = res | bytes[3];

    *data = res;

    return 0;
}

//writes i node to disk block
void write_i_node_to_block(u_int32_t* ptr, u_int32_t block_num, iNode* i_node) {
    uint8_t buf[BLOCK_SIZE*2]; read_blocks(block_num, 2, buf);
    write_int_to_buf(i_node->mode, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->link_cnt, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->uid, ptr, buf, BLOCK_SIZE);
    write_int_to_buf(i_node->size, ptr, buf, BLOCK_SIZE);
    for (u_int32_t i = 0; i < 12; i++) {
        write_int_to_buf(i_node->data_ptrs[i], ptr, buf, BLOCK_SIZE);
    }
    write_int_to_buf(i_node->indirectPointer, ptr, buf, BLOCK_SIZE);
    write_blocks(block_num, 2, buf);
}

// reads i node from disk block
void read_i_node_from_block(u_int32_t* ptr, u_int32_t block_num, iNode* i_node) {
    uint8_t buf[BLOCK_SIZE*2]; read_blocks(block_num, 2, buf);
    read_int_from_buf(&i_node->mode, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->link_cnt, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->uid, ptr, buf, BLOCK_SIZE);
    read_int_from_buf(&i_node->size, ptr, buf, BLOCK_SIZE);
    for (u_int32_t i = 0; i < 12; i++) {
        read_int_from_buf(&i_node->data_ptrs[i], ptr, buf, BLOCK_SIZE);
    }
    read_int_from_buf(&i_node->indirectPointer, ptr, buf, BLOCK_SIZE);
}

//gets the block number and byte pointer to the block where the i-node is stored
void get_i_node_block_coords(u_int32_t i_node_num, u_int32_t* block_num, u_int32_t* ptr) {
    *block_num = (i_node_num * I_NODE_SIZE_DISK) / BLOCK_SIZE + 2;
    *ptr = i_node_num * I_NODE_SIZE_DISK % BLOCK_SIZE;
}

//gets the block number and byte pointer to the block where the data is stored
void get_block_coords_from_rw_ptr(u_int32_t rw_pointer, u_int32_t* block_num, u_int32_t* ptr) {
    *block_num = rw_pointer / BLOCK_SIZE;
    *ptr = rw_pointer % BLOCK_SIZE;
}

//calculate the number of blocks needed to store data, starting from ptr
void calculate_num_of_blocks(u_int32_t ptr, u_int32_t length, u_int32_t* num_of_blocks) {
    *num_of_blocks = (ptr + length + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

// writes i node to i node table (disk and in-memory cache)
u_int32_t write_to_i_node_table(iNode* i_node) {

    u_int32_t i_node_num = i_node->uid;

    printf("Writing i-node %d to i-node table...\n", i_node_num);

    //update in-memory structures 
    i_node_table[i_node_num] = i_node;
    i_node_table_bitmap[i_node_num] = 1;

    //find which block to write to in i node table
    u_int32_t block_num, ptr; get_i_node_block_coords(i_node_num, &block_num, &ptr);

    //write i node to block on disk
    write_i_node_to_block(&ptr, block_num, i_node);

    //update i node bitmap on disk
    uint8_t bitmap_block[BLOCK_SIZE]; read_blocks(0, 1, bitmap_block); //super block
    u_int32_t start_ptr = START_BYTE_I_NODE_BITMAP;
    write_to_bitmap_block_buffer(bitmap_block, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr);
    write_blocks(0, 1, bitmap_block);

    printf("Done writing i-node %d to i-node table\n", i_node_num);
    return 0;
}


// read from i node table (disk and in-memory cache)
u_int32_t read_from_i_node_table(u_int32_t i_node_num, iNode** i_node_container, u_int32_t from_disk) {
    printf("Reading i-node %d from i-node table...\n", i_node_num);

    //check if i-node is in memory
    if (i_node_table_bitmap[i_node_num] == 0) {
        printf("Error: i-node %d not in memory\n", i_node_num);
        return -1;
    }

    //get i-node
    if (from_disk) {
        //find which block to read from in i node table
        u_int32_t block_num, ptr; get_i_node_block_coords(i_node_num, &block_num, &ptr);

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
    uint8_t bitmap_block[BLOCK_SIZE]; read_blocks(0, 1, bitmap_block); //super block
    u_int32_t start_ptr = START_BYTE_I_NODE_BITMAP;
    //convert i-node bitmap block to i-node bitmap
    read_from_bitmap_block_buffer(bitmap_block, i_node_table_bitmap, I_NODE_TABLE_SIZE, start_ptr);
    printf("Done loading i-node bitmap from disk\n");
}


//get specific data block using i-node
u_int32_t get_block(iNode* i_node, u_int32_t block_num, uint8_t buf[]) {
    printf("Getting block %d...\n", block_num);

    u_int32_t num_of_blocks_for_i_node = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    if (block_num >= num_of_blocks_for_i_node) {
        printf("Error: block number out of bounds\n");
        return -1;
    }

    if (block_num < 12) {
        //direct pointer
        read_blocks(i_node->data_ptrs[block_num], 1, buf);
    } else {
        //indirect pointer
        uint8_t indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
        u_int32_t ptr = (block_num - 12) * FIELD_SIZE;
        u_int32_t block_to_read; read_int_from_buf(&block_to_read, &ptr, indirect_block, BLOCK_SIZE);
        read_blocks(block_to_read, 1, buf);
    }
    printf("Done getting block %d\n", block_num);
    return 0;
}

//get specified amount of blocks from i-node until 
void get_blocks(iNode* i_node, u_int32_t start_block_num, u_int32_t num_of_blocks, uint8_t buf[]) {
    printf("Getting blocks...\n");
    for (u_int32_t i = 0; i < num_of_blocks; i++) {
        if (get_block(i_node, start_block_num + i, &buf[i*BLOCK_SIZE]) == -1) {
            return;
        }
    }
    printf("Done getting blocks\n");
}

// TODO abstract the block num checking function (<12 or indirect)
// marks the index-th slot with the data block number in-memory and on disk
u_int32_t mark_data_block_on_i_node(iNode* i_node, u_int32_t data_block_num, u_int32_t index) {  
    printf("Marking data block %d on i-node...\n", data_block_num);
    if (index < 12) {
        //direct pointer
        i_node->data_ptrs[index] = data_block_num;
        write_to_i_node_table(i_node);
    } else if (index < 12 + BLOCK_SIZE / FIELD_SIZE) {
        //indirect pointer
        uint8_t indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
        u_int32_t ptr = (index - 12) * FIELD_SIZE;
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
u_int32_t find_available_data_block(u_int32_t* block_num) {
    printf("Finding available data block...\n");
    u_int32_t found = 0;
    for (u_int32_t i = 0; i < NUM_OF_DATA_BLOCKS; i++) {
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

// reserve data block by updating corresponding free bitmap entry
void reserve_data_block(u_int32_t block_num) {
    printf("Reserving data block %d...\n", block_num);
    //update free bitmap
    free_bitmap[block_num] = 1;
    //update free bitmap on disk
    u_int32_t buf_size = BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS;
    uint8_t bitmap_block[buf_size]; read_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    u_int32_t start_ptr = 0;
    write_to_bitmap_block_buffer(bitmap_block, free_bitmap, NUM_OF_DATA_BLOCKS, start_ptr);
    write_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block);
    printf("Done reserving data block %d\n", block_num);
}

// finds and reserves a data block, and writes number of block to block_num
void allocate_data_block(u_int32_t* block_num) {
    printf("Allocating data block...\n");
    u_int32_t res = find_available_data_block(block_num);
    if (res == -1) {
        printf("Error: no available data blocks\n");
        return;
    }
    reserve_data_block(*block_num);
    printf("Done allocating data block\n");
}

//save specific data block using i-node
u_int32_t save_block(iNode* i_node, u_int32_t block_num, uint8_t buf[]) {
    printf("Saving block %d...\n", block_num);
    
    u_int32_t num_of_blocks_for_i_node = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (block_num >= num_of_blocks_for_i_node) {
        printf("Error: block number out of bounds\n");
        return -1;
    }

    if (block_num < 12) {
        //direct pointer
        write_blocks(i_node->data_ptrs[block_num], 1, buf);
    } else if (block_num < 12 + BLOCK_SIZE / FIELD_SIZE) {
        //indirect pointer
        uint8_t indirect_block[BLOCK_SIZE]; read_blocks(i_node->indirectPointer, 1, indirect_block);
        u_int32_t ptr = (block_num - 12) * FIELD_SIZE;
        u_int32_t block_num_to_write; read_int_from_buf(&block_num_to_write, &ptr, indirect_block, BLOCK_SIZE);
        write_blocks(block_num_to_write, 1, buf);
    } else {
        printf("Error: block number out of bounds\n");
        return -1;
    }
    printf("Done saving block %d\n", block_num);
    return 0;
}

//save specified amount of blocks from i-node
void save_blocks(iNode* i_node, u_int32_t start_block_num, u_int32_t num_of_blocks, uint8_t buf[]) {
    printf("Saving blocks...\n");
    for (u_int32_t i = 0; i < num_of_blocks; i++) {
        save_block(i_node, start_block_num + i, &buf[i*BLOCK_SIZE]);
    }
    printf("Done saving blocks\n");
}

// loads data from blocks into buffer
u_int32_t load_data_from_i_node(iNode* i_node, uint8_t buf[]) {
    printf("Loading data from blocks...\n");

    u_int32_t num_of_blocks = i_node->size + BLOCK_SIZE - 1 / BLOCK_SIZE;

    if (num_of_blocks == 0) {
        printf("Nothing to load\n");
        return -1;
    }

    for (u_int32_t i = 0; i < num_of_blocks; i++) {
        get_block(i_node, i, &buf[i*BLOCK_SIZE]);
    }

    printf("Done loading data from blocks\n");
    return 0;
}

//find available i-node table slot 
u_int32_t find_available_i_node(u_int32_t* i_node_num) {
    printf("Finding available i-node...\n");
    u_int32_t found = 0;
    for (u_int32_t i = 0; i < I_NODE_TABLE_SIZE; i++) {
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



//writes the superblock of the disk, moves pointer also to next avail byte in block
u_int32_t write_superblock(u_int32_t* ptr,u_int32_t magic,u_int32_t block_size,u_int32_t max_block,u_int32_t i_node_table_size,u_int32_t root_dir_i_node,u_int32_t num_of_files) {
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
u_int32_t validate_superblock() {
    printf("Validating superblock...\n");
    uint8_t buffer[BLOCK_SIZE]; read_blocks(0, 1, buffer);
    u_int32_t ptr = 0;
    u_int32_t magic; read_int_from_buf(&magic, &ptr, buffer, BLOCK_SIZE);
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
    for (u_int32_t i = 0; i < I_NODE_TABLE_SIZE; i++) {
        //if i-node is used
        if (i_node_table_bitmap[i]) {
            read_from_i_node_table(i, &i_node_table[i], 1); //this function will refresh the i-node in the cache
        }
    }
    printf("Done loading i-node table\n");
}

//initializes an empty i-node
void init_empty_i_node(iNode* i_node, u_int32_t id) {
    i_node->mode = 0;
    i_node->link_cnt = 0;
    i_node->uid = id;
    i_node->size = 0;
    for (u_int32_t i = 0; i < 12; i++) {
        i_node->data_ptrs[i] = 0;
    }
    i_node->indirectPointer = 0;
}

//loads the data of the superblock into the buffer
u_int32_t load_superblock(u_int32_t* ptr, u_int32_t* block_size, u_int32_t* max_block, u_int32_t* i_node_table_size, u_int32_t* root_dir_i_node, u_int32_t* num_of_files) {
    printf("Loading superblock...\n");
    uint8_t buffer[BLOCK_SIZE]; read_blocks(0, 1, buffer);
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
    u_int32_t ptr = 0;
    for (u_int32_t i = 0; i < root_dir.num_of_entries; i++) {
        //create entry
        DirEntry* entry = malloc(sizeof(DirEntry));
        //read entry from data
        entry->used = data[ptr++];
        for (u_int32_t j = 0; j < MAX_NAME_SIZE; j++) {
            entry->name[j] = data[ptr];
            ptr++;
        }
        read_int_from_buf(&entry->i_node_num, &ptr, data, BLOCK_SIZE);
        //add entry to root directory
        root_dir.entries[i] = entry;
    }
    printf("Done loading root directory\n");
}

void mksfs(u_int32_t fresh) {
    if (fresh) { // create new file system
        init_fresh_disk("sfs_disk.disk", BLOCK_SIZE, MAX_BLOCK);
        
        /* STEP 1: CREATE SUPERBLOCK*/

        printf("CREATING SUPERBLOCK\n");
        u_int32_t ptr = 0;
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
        u_int32_t ptr = 4;
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
        uint8_t root_dir_buf[BLOCK_SIZE + root_dir_i_node->size]; load_data_from_i_node(root_dir_i_node, root_dir_buf);
        load_root_dir(root_dir_buf);

        /* GET FREE BITMAP INFORMATION */

        // load free bitmap into memory
        uint8_t bitmap_block_buffer[BLOCK_SIZE*NUM_OF_BITMAP_BLOCKS]; read_blocks(START_BLOCK_BITMAP, NUM_OF_BITMAP_BLOCKS, bitmap_block_buffer);
        read_from_bitmap_block_buffer(bitmap_block_buffer, free_bitmap, NUM_OF_DATA_BLOCKS, 0);

    }
}

// initializes a directory entry with the file name and i_node_num
void init_entry(DirEntry* entry, char* name, u_int32_t i_node_num) {
    printf("Creating entry...\n");
    entry->used = 1;
    for (u_int32_t i = 0; i < MAX_NAME_SIZE; i++) {
        entry->name[i] = name[i];
    }
    entry->i_node_num = i_node_num;
    printf("Done creating entry\n");
}

// writes a directory entry to disk
void write_dir_entry_to_disk(DirEntry* entry, u_int32_t idx) {
    u_int32_t block_num = DIR_ENTRY_SIZE_DISK * idx / BLOCK_SIZE;
    u_int32_t ptr = DIR_ENTRY_SIZE_DISK * idx % BLOCK_SIZE;

    //read buffer from disk 
    uint8_t buffer[BLOCK_SIZE*2];
    get_block(i_node_table[ROOT_DIR_INODE_IDX], block_num, &buffer[0]);
    get_block(i_node_table[ROOT_DIR_INODE_IDX], block_num+1, &buffer[BLOCK_SIZE]);

    //modify buffer
    buffer[ptr++] = entry->used;
    for (u_int32_t i = 0; i < MAX_NAME_SIZE; i++) {
        buffer[ptr++] = entry->name[i];
    }
    write_int_to_buf(entry->i_node_num, &ptr, buffer, BLOCK_SIZE);

    //write buffer to disk
    save_block(i_node_table[ROOT_DIR_INODE_IDX], block_num, &buffer[0]);
    save_block(i_node_table[ROOT_DIR_INODE_IDX], block_num+1, &buffer[BLOCK_SIZE]);

}

//creates an entry in the directory table with the file name and i_node_num
u_int32_t create_new_file(char* name, u_int32_t* i_node_num) {
    printf("Creating new file...\n");
    
    //create i-node
    u_int32_t res = find_available_i_node(i_node_num);
    if (res != 0) {
        printf("Error: no available i-nodes\n");
        return res;
    }
    iNode* new_i_node = malloc(sizeof(iNode));
    init_empty_i_node(new_i_node, *i_node_num);
    
    //create entry in root directory
    DirEntry* entry = malloc(sizeof(DirEntry));
    init_entry(entry, name, *i_node_num);

    u_int32_t i;
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

// u_int32_t sfs_getnextfilename(char*) {

// }

// u_int32_t sfs_getfilesize(const char*) {

// }

//checks if file exists in root directory, if it does also get the i-node number
u_int32_t does_file_exist(char* name, u_int32_t* i_node_num) {
    for (u_int32_t i = 0; i < root_dir.num_of_entries; i++) {
        if (strcmp(root_dir.entries[i]->name, name) == 0) {
            *i_node_num = root_dir.entries[i]->i_node_num;
            return 1;
        }
    }
    return 0;
}

//acts the same way as fopen(), returns a file descriptor
u_int32_t sfs_fopen(char* name) {

    printf("OPENING FILE...\n");
    //check length of name
    u_int32_t name_len = strlen(name);
    if (name_len >= MAX_NAME_SIZE) {
        printf("Error: name too long\n");
        return -1;
    }

    u_int32_t i_node_num;

    //check if file exists
    u_int32_t exists = does_file_exist(name, &i_node_num);

    //if file does not exist, create it 
    if (!exists) {
        if (create_new_file(name, &i_node_num) != 0) {
            printf("Error: could not create file\n");
            return -1;
        }
    }

    //create file descriptor 
    for (u_int32_t i = 0; i < UPPER_LIMIT_FD_TABLE; i++) {
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
}

void sfs_fclose(u_int32_t fd) {
    printf("Closing file...\n");
    fd_table[fd].used = 0;
    printf("Done closing file\n");
}

//expands i-node to desired new length
u_int32_t expand_i_node(iNode* i_node, u_int32_t num_of_bytes) {
    //     u_int32_t block_num; allocate_data_block(&block_num);
    //     mark_data_block_on_i_node(i_node, block_num);
    printf("Expanding i-node...\n");

    // get number of data blocks currently reserved for i-node
    u_int32_t num_of_blocks_i_node = (i_node->size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    //check if we need new data blocks
    u_int32_t num_of_blocks = ((i_node->size-1) % BLOCK_SIZE + num_of_bytes) / BLOCK_SIZE;
    for (u_int32_t i = 0; i < num_of_blocks; i++) {
        u_int32_t block_num; allocate_data_block(&block_num);
        if (!mark_data_block_on_i_node(i_node, block_num, num_of_blocks_i_node + i)) {
            printf("Error: could not mark data block on i-node\n");
            return -1;
        };
    }

    //update i-node size
    i_node->size += num_of_bytes;
}

u_int32_t sfs_fwrite(u_int32_t fd, char* buf, u_int32_t length) {
    printf("Writing to file...\n");

    FileDescriptor file_descriptor = fd_table[fd];

    iNode* i_node; read_from_i_node_table(file_descriptor.i_node_num, &i_node, 0);

    u_int32_t rw_pointer = file_descriptor.rw_pointer;
    u_int32_t block_num, ptr, num_of_blocks;

    get_block_coords_from_rw_ptr(rw_pointer, &block_num, &ptr);
    calculate_num_of_blocks(ptr, length, &num_of_blocks);

    //populate buffer with the data with the blocks we will be changing
    uint8_t data_buf[BLOCK_SIZE*num_of_blocks];
    get_blocks(i_node, block_num, num_of_blocks, data_buf);

    //write data to buffer
    for (u_int32_t i = 0; i < length; i++) {
        data_buf[ptr++] = buf[i];
    }

    //check if we need to expand i-node size
    if (rw_pointer + length >= i_node->size) {
        if (!expand_i_node(i_node, rw_pointer + length - i_node->size + 1)) {
            printf("Error: could not expand i-node\n");
            return -1;
        }
    }

    //save buffer to disk
    save_blocks(i_node, block_num, num_of_blocks, data_buf);

    //update file descriptor
    file_descriptor.rw_pointer += length;

    printf("Done writing to file\n");
    return 0;
}

u_int32_t sfs_fread(u_int32_t fd, char* buf, u_int32_t length) {
    printf("Reading from file...\n");

    FileDescriptor file_descriptor = fd_table[fd];
    iNode* i_node; read_from_i_node_table(file_descriptor.i_node_num, &i_node, 0);

    u_int32_t rw_pointer = file_descriptor.rw_pointer;
    u_int32_t block_num, ptr, num_of_blocks;

    get_block_coords_from_rw_ptr(rw_pointer, &block_num, &ptr);
    calculate_num_of_blocks(ptr, length, &num_of_blocks);

    //intermediate buffer to store data from disk
    uint8_t data_buf[BLOCK_SIZE*num_of_blocks];
    get_blocks(i_node, block_num, num_of_blocks, data_buf);

    //store data in buffer
    for (u_int32_t i = 0; i < length; i++) {
        buf[i] = data_buf[ptr++];
    }

    printf("Done reading from file\n");
    return 0;
}

u_int32_t sfs_fseek(u_int32_t fd, u_int32_t offset) {
    printf("Seeking file...\n");

    FileDescriptor file_descriptor = fd_table[fd];
    file_descriptor.rw_pointer = offset;

    printf("Done seeking file\n");
    return 0;
}

// u_int32_t sfs_remove(char*) {

// }