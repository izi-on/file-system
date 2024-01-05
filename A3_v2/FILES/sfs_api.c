#include <stdlib.h>
#include <strings.h>
#include <inttypes.h>
#include "sfs_api.h"
#include <stdio.h>
#include <string.h>
#include "disk_emu.h"

#define DIR_POINTERS 12
#define MAGIC 0xABC
#define NUM_OF_INODES 100
#define BLOCK_SIZE 1024
#define BITMAP_BLOCK BLOCK_SIZE - 1
#define ROOT_DIR_BLOCK 0
#define NUM_OF_BLOCKS 1024
#define MAX_FILE_SIZE BLOCK_SIZE *((BLOCK_SIZE / sizeof(int)) + 12) // block size * num of possible blocks on i node
#define FS_NAME "DISK.disk"
#define MAX_FILE_NAME 20

#define INVALID -1
// Create in-memory structures

typedef struct
{
	int mode;
	int link_count;
	int uid;
	int gid;
	int size;
	int direct_p[12];
	int indirect_pointer;
} i_node_t;

typedef struct
{
	int inode_number;
	int rwpointer;
	i_node_t *inode;
} file_descriptor_table_t;

typedef struct
{
	int magic;
	int block_size;
	int file_system_size;
	int inode_table_length;
	int root_directory;
} super_block_t;

typedef struct
{
	int i_node;
	char file_name[MAX_FILE_NAME + 1];
} directory_entry_t;

super_block_t super_block_var;
i_node_t i_node_table[NUM_OF_INODES];
directory_entry_t root_dir[NUM_OF_INODES];
file_descriptor_table_t fd_table[NUM_OF_INODES];
int directory_location;
int i_node_table_bitmap[NUM_OF_INODES];
int indirect_pointer_block[BLOCK_SIZE / sizeof(int)];

// Create bit map to keep track of free blocks using an array
int bit_map[BLOCK_SIZE / 8] = {[0 ...(BLOCK_SIZE / 8 - 1)] = UINT8_MAX};

// Find the inode number of the given file
int get_directory_inode(const char *name)
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		if (root_dir[i].i_node != -1 && strcmp(root_dir[i].file_name, name) == 0)
		{
			return root_dir[i].i_node;
		}
	}
	perror("Error getting directory inode: File does not exist\n");
	return -1;
}

#define BITS_PER_BYTE 8

// Sets the specified index in the bitmap as USED
void set_index_bit(int idx)
{
	if (idx < 0 || idx >= BLOCK_SIZE)
	{
		fprintf(stderr, "Error: Index out of range\n");
		return;
	}

	int i = idx / BITS_PER_BYTE;
	int bit = idx % BITS_PER_BYTE;
	bit_map[i] = bit_map[i] & ~(1 << bit);
}

#define BITS_PER_BYTE 8
#define BITMAP_SIZE (BLOCK_SIZE / BITS_PER_BYTE)

// Get the first available bit in the bitmap
int get_index_bit()
{
	int i = 0;
	while (bit_map[i] == 0)
	{
		i++;
		if (i >= BITMAP_SIZE)
		{
			fprintf(stderr, "Error: No available bits in the bitmap\n");
			return -1;
		}
	}

	int bit = ffs(bit_map[i]) - 1;
	bit_map[i] = bit_map[i] & ~(1 << bit);
	return i * BITS_PER_BYTE + bit;
}

#define BITS_PER_BYTE 8

// Sets the specified index in the bitmap as FREE
void remove_index_bit(int idx)
{
	if (idx < 0 || idx >= BLOCK_SIZE)
	{
		fprintf(stderr, "Error: Index out of range\n");
		return;
	}

	int i = idx / BITS_PER_BYTE;
	int bit = idx % BITS_PER_BYTE;
	bit_map[i] = bit_map[i] | (1 << bit);
}

#define FREE_INODE 0

// Find the first available inode
int find_free_inode()
{
	for (int i = 1; i < NUM_OF_INODES; i++)
	{
		if (i_node_table_bitmap[i] == FREE_INODE)
		{
			i_node_table_bitmap[i] = 1;
			return i;
		}
	}
	fprintf(stderr, "Error: No available inodes\n");
	return -1;
}

#define EMPTY -1
#define UNUSED 0
#define USED 1

// Initialize the I-Nodes
void init_i_nodes()
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		i_node_table[i].mode = EMPTY;
		i_node_table[i].link_count = EMPTY;
		i_node_table[i].uid = EMPTY;
		i_node_table[i].gid = EMPTY;
		i_node_table[i].size = EMPTY;
		i_node_table[i].indirect_pointer = EMPTY;

		for (int j = 0; j < 12; j++)
		{
			i_node_table[i].direct_p[j] = EMPTY;
		}
		i_node_table_bitmap[i] = UNUSED;
	}
}

// Function to calculate the number of blocks
int calculate_blocks(size_t size)
{
	int blocks = size / BLOCK_SIZE;
	if (size % BLOCK_SIZE != 0)
	{
		blocks += 1;
	}
	return blocks;
}

// Initialize the file descriptor table
void init_fd_table()
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		fd_table[i].inode_number = EMPTY;
		fd_table[i].rwpointer = EMPTY;
	}
}

// Initialize the root directory
void init_root_dir()
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		root_dir[i].i_node = EMPTY;
		for (int j = 0; j < MAX_FILE_NAME; j++)
		{
			root_dir[i].file_name[j] = '0';
		}
	}
}

// Initialize the first inode
void init_first_inode(int root_dirBlocks)
{
	i_node_table_bitmap[0] = USED;
	i_node_table[0].mode = 0;
	i_node_table[0].link_count = root_dirBlocks;
	i_node_table[0].uid = 0;
	i_node_table[0].gid = 0;
	i_node_table[0].size = EMPTY;
	i_node_table[0].indirect_pointer = EMPTY;
}

// Initialize the super block
void init_super_block()
{
	super_block_var.magic = MAGIC;
	super_block_var.block_size = BLOCK_SIZE;
	super_block_var.file_system_size = NUM_OF_BLOCKS;
	super_block_var.inode_table_length = NUM_OF_INODES;
	super_block_var.root_directory = 0;
}

// Read a block from the disk
void read_block(int block, void *buffer, size_t size)
{
	void *temp = malloc(BLOCK_SIZE);
	read_blocks(block, 1, temp);
	memcpy(buffer, temp, size);
	free(temp);
}

// Initialize the disk and read the super block, inode table bitmap, and bit map
void init_disk_and_read_blocks()
{
	init_disk(FS_NAME, BLOCK_SIZE, NUM_OF_BLOCKS);
	read_block(0, &super_block_var, sizeof(super_block_var));
	read_block(ROOT_DIR_BLOCK, &i_node_table_bitmap, sizeof(i_node_table_bitmap));
	read_block(BITMAP_BLOCK, &bit_map, sizeof(bit_map));
}

// Calculate the number of blocks occupied by the inode table
int calculate_inode_blocks()
{
	int inodeBlocks = sizeof(i_node_table) / BLOCK_SIZE;
	if (sizeof(i_node_table) % BLOCK_SIZE != 0)
	{
		inodeBlocks += 1;
	}
	return inodeBlocks;
}

// Read the root directory
void read_root_dir()
{
	void *temp = malloc(BLOCK_SIZE * i_node_table[0].link_count);
	read_blocks(i_node_table[0].direct_p[0], i_node_table[0].link_count, temp);
	memcpy(&root_dir, temp, sizeof(root_dir));
	free(temp);
}

// Create the file system
// fresh flag signals if the file system should be created from scratch or if it already exists.
void mksfs(int fresh)
{
	// The file system should be created from scratch.
	init_fd_table();

	if (fresh == 1)
	{
		// initialize pointers for root directory
		int root_pointer[12];
		// Initialize the fresh disk, calling the provided funciton
		init_fresh_disk(FS_NAME, BLOCK_SIZE, NUM_OF_BLOCKS);

		init_root_dir();

		init_i_nodes();

		// Calculate the number of blocks occupied by the inode table and the root directory
		int inodeBlocks = calculate_blocks(sizeof(i_node_table));
		int root_dirBlocks = calculate_blocks(sizeof(root_dir));

		// Initialize root_pointer array
		for (int i = 0; i < root_dirBlocks; i++)
		{
			root_pointer[i] = i + 1 + inodeBlocks;
		}

		for (int i = 0; i < root_dirBlocks + inodeBlocks + 1; i++)
		{
			// Create space for rest of the blocks
			set_index_bit(i);
		}

		set_index_bit(ROOT_DIR_BLOCK); // Set the root directory block to be used
		set_index_bit(BITMAP_BLOCK);   // Set the bitmap block to be used

		init_first_inode(root_dirBlocks);
		init_super_block();

		for (int i = 0; i < 12; i++)
		{
			i_node_table[0].direct_p[i] = root_pointer[i];
		}

		directory_location = 0; // Used for tracking the current directory location.
		void *temp = malloc(BLOCK_SIZE * root_dirBlocks);
		memcpy(temp, &root_dir, sizeof(root_dir));
		// Write the initialized blocks to disk
		write_blocks(0, 1, &super_block_var);
		write_blocks(i_node_table[0].direct_p[0], root_dirBlocks, temp);
		write_blocks(1, inodeBlocks, &i_node_table);
		write_blocks(ROOT_DIR_BLOCK, 1, &i_node_table_bitmap);
		write_blocks(BITMAP_BLOCK, 1, &bit_map);
		free(temp);
	}
	else
	{
		// The file system already exists, so we have to read it from disk.
		init_disk_and_read_blocks();
		init_root_dir();
		read_root_dir();
		init_fd_table();
	}
}

// Check if the directory location is valid
int is_valid_directory_location()
{
	return directory_location < NUM_OF_INODES;
}

// Reset the directory location
void reset_directory_location()
{
	directory_location = 0;
}

// Get the name of the next file in directory
int sfs_getnextfilename(char *fname)
{
	if (!is_valid_directory_location())
	{
		reset_directory_location();
		return 0;
	}

	while (root_dir[directory_location].i_node == EMPTY)
	{
		directory_location++;
		if (!is_valid_directory_location())
		{
			reset_directory_location();
			return 0;
		}
	}

	strcpy(fname, root_dir[directory_location].file_name);
	directory_location++;
	return 1;
}

// Get the size of the given file
int sfs_getfilesize(const char *path)
{
	int i_node_id = get_directory_inode(path);
	if (i_node_id != -1)
	{
		return i_node_table[i_node_id].size;
	}
	else
	{
		return -1;
	}
}

// Check if the file name is valid
int is_valid_file_name(char *name)
{
	unsigned int length = strlen(name);
	if (length > MAX_FILE_NAME)
	{
		perror("Error opening file: File name exceeds maximum file name length\n");
		return 0;
	}
	return 1;
}

// Find the first available entry in the file descriptor table
int find_available_fd_index()
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		if (fd_table[i].inode_number == INVALID)
		{
			return i;
		}
	}
	return INVALID;
}

// Check if the file is already open
int is_file_already_open(int inode_idx)
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		if (fd_table[i].inode_number == inode_idx)
		{
			return 1;
		}
	}
	return 0;
}

// Open the file
void open_file(int fd_index, int inode_idx)
{
	fd_table[fd_index].inode_number = inode_idx;
	fd_table[fd_index].inode = &(i_node_table[inode_idx]);
	fd_table[fd_index].rwpointer = i_node_table[inode_idx].size;
}

// Allocate an inode for the file
int allocate_inode()
{
	int inode_idx = find_free_inode();
	if (inode_idx == INVALID)
	{
		perror("Error opening the file: Failed to create the file, no more free inodes\n");
	}
	return inode_idx;
}

// Find the first available spot in the root directory
int find_available_directory_index()
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		if (root_dir[i].i_node == INVALID)
		{
			return i;
		}
	}
	perror("Error opening the file: Failed to create the file, directory full\n");
	return INVALID;
}

// Retrieve the data from bitmap
int retrieve_data_from_bitmap()
{
	int pointer = get_index_bit();
	if (pointer == 0)
	{
		perror("Error opening the file: Failed to create the file, no more blocks available\n");
	}
	return pointer;
}

// Initialize the pointers
void initialize_pointers(int pointers[])
{
	pointers[0] = retrieve_data_from_bitmap();
	for (int i = 1; i < DIR_POINTERS; i++)
	{
		pointers[i] = INVALID;
	}
}

// Initialize the I-Node for the created file
void initialize_inode(int inode_idx, int pointers[])
{
	i_node_table_bitmap[inode_idx] = 1;
	i_node_table[inode_idx].mode = 0;
	i_node_table[inode_idx].link_count = 1;
	i_node_table[inode_idx].uid = 0;
	i_node_table[inode_idx].gid = 0;
	i_node_table[inode_idx].size = 0;
	i_node_table[inode_idx].indirect_pointer = INVALID;
	for (int j = 0; j < DIR_POINTERS; j++)
	{
		i_node_table[inode_idx].direct_p[j] = pointers[j];
	}
}

// Calculate the number of blocks needed
int calculate_blocks_needed(size_t size)
{
	int blocks = size / BLOCK_SIZE;
	if (size % BLOCK_SIZE != 0)
	{
		blocks += 1;
	}
	return blocks;
}

// Allocate memory for the root directory
void *allocate_memory_for_root_dir(int blocks)
{
	void *temp = malloc(BLOCK_SIZE * blocks);
	memcpy(temp, &root_dir, sizeof(root_dir));
	return temp;
}

// Write data to disk
void write_data_to_disk()
{
	int root_dir_blocks = calculate_blocks_needed(sizeof(root_dir));
	void *temp = allocate_memory_for_root_dir(root_dir_blocks);

	int inode_blocks = calculate_blocks_needed(sizeof(i_node_table));

	// Write root directory to disk with write_blocks() function
	write_blocks(i_node_table[0].direct_p[0], root_dir_blocks, temp);
	free(temp);

	// Write I-Node table to disk with write_blocks() function
	write_blocks(1, inode_blocks, &i_node_table);

	// Write I-Node status to disk with write_blocks() function
	write_blocks(ROOT_DIR_BLOCK, 1, &i_node_table_bitmap);

	// Write bitmap to disk with write_blocks() function
	write_blocks(BITMAP_BLOCK, 1, &bit_map);
}

// opens the given file
int sfs_fopen(char *name)
{

	if (!is_valid_file_name(name))
	{
		return INVALID;
	}

	int fd_index = find_available_fd_index();
	if (fd_index == INVALID)
	{
		perror("Error opening file: No available file descriptor\n");
		return INVALID;
	}

	if (fd_index != -1)
	{
		// find the inode number of the given file
		int i_node_idx = get_directory_inode(name);
		// check if the file exists
		if (i_node_idx != -1)
		{
			if (is_file_already_open(i_node_idx))
			{
				perror("Error opening the file: The file is already open");
				return INVALID;
			}

			open_file(fd_index, i_node_idx);
			return fd_index;
		}
		else
		{
			// The file does not exists, we have to create it

			int inode_idx = allocate_inode();
			if (inode_idx == INVALID)
			{
				return INVALID;
			}

			int directory_index = find_available_directory_index();
			if (directory_index == INVALID)
			{
				return INVALID;
			}

			int pointers[DIR_POINTERS];
			initialize_pointers(pointers);

			fd_table[fd_index].inode_number = inode_idx;
			root_dir[directory_index].i_node = inode_idx;
			strcpy(root_dir[directory_index].file_name, name);

			initialize_inode(inode_idx, pointers);

			fd_table[fd_index].inode = &(i_node_table[inode_idx]);
			fd_table[fd_index].rwpointer = i_node_table[inode_idx].size;

			i_node_table[0].size += 1;
			write_data_to_disk();

			return fd_index;
		}
	}
	else
	{
		perror("Error opening file: No file descripter index available for specified file\n");
		return -1;
	}
}

// Check if the file is already closed
int is_file_closed(int fileID)
{
	return fd_table[fileID].inode_number == -1;
}

// Close the given file
void close_file(int fileID)
{
	fd_table[fileID].inode_number = -1;
	fd_table[fileID].rwpointer = -1;
}

// Close the given file and return status
int sfs_fclose(int fileID)
{
	if (is_file_closed(fileID))
	{
		return -1;
	}
	close_file(fileID);
	return 0;
}

// Check if the file ID is valid
int is_valid_file_id(int fileID)
{
	return fileID >= 0;
}

// Check if the inode ID is valid
int is_valid_inode_id(int inodeId)
{
	return inodeId != INVALID;
}

// Check if the file size exceeds the maximum file size
int is_file_size_exceeding_limit(int need)
{
	return need > MAX_FILE_SIZE;
}

// Calculate the needed blocks for writing
double calculate_needed_blocks(int need)
{
	double neededBlocks = need / BLOCK_SIZE;
	if (need % BLOCK_SIZE != 0)
	{
		neededBlocks += 1;
	}
	return neededBlocks;
}

// Handle indirect pointers
int handle_indirect_pointers(int inodeId, double extraBlocks)
{
	void *temp = malloc(BLOCK_SIZE);
	if (i_node_table[inodeId].link_count > 12)
	{
		read_blocks(i_node_table[inodeId].indirect_pointer, 1, temp);
		memcpy(&indirect_pointer_block, temp, BLOCK_SIZE);
	}
	else if (i_node_table[inodeId].link_count + extraBlocks > 12)
	{
		int indirect = get_index_bit();
		if (indirect == 0)
		{
			free(temp);
			return INVALID;
		}
		i_node_table[inodeId].indirect_pointer = indirect;
	}
	free(temp);
	return 0;
}

// Assign the free blocks from bitmap
int assign_free_blocks(int inodeId, double extraBlocks)
{
	int newBlock = 0;
	if (extraBlocks > 0)
	{
		for (int i = i_node_table[inodeId].link_count; i < i_node_table[inodeId].link_count + extraBlocks; i++)
		{
			newBlock = get_index_bit();
			if (newBlock != 0)
			{
				if (i >= 12)
				{
					indirect_pointer_block[i - 12] = newBlock;
				}
				else
				{
					i_node_table[inodeId].direct_p[i] = newBlock;
				}
			}
			else
			{
				perror("Error writing file: No more block available!\n");
				return INVALID;
			}
		}
	}
	else
	{
		extraBlocks = 0;
	}
	return 0;
}

// Load the file into memory from each pointer
void *load_file_into_memory(int inodeId, int startBlock, int endBlock)
{
	void *temp = malloc(BLOCK_SIZE * endBlock);
	for (int i = startBlock; i < i_node_table[inodeId].link_count && i < endBlock; i++)
	{
		if (i >= 12)
		{
			read_blocks(indirect_pointer_block[i - 12], 1, (temp + (i - startBlock) * BLOCK_SIZE));
		}
		else
		{
			read_blocks(i_node_table[inodeId].direct_p[i], 1, (temp + (i - startBlock) * BLOCK_SIZE));
		}
	}
	return temp;
}

// Write pointers to disk
void write_pointers_to_disk(int inodeId, int startBlock, int endBlock, void *temp)
{
	for (int i = startBlock; i < endBlock; i++)
	{
		if (i >= 12)
		{
			write_blocks(indirect_pointer_block[i - 12], 1, (temp + (i - startBlock) * BLOCK_SIZE));
		}
		else
		{
			write_blocks(i_node_table[inodeId].direct_p[i], 1, (temp + ((i - startBlock) * BLOCK_SIZE)));
		}
	}
}

// Update the inode
void update_inode(int inodeId, int need, double extraBlocks, int fileID)
{
	if (i_node_table[inodeId].size < need)
	{
		i_node_table[inodeId].size = need;
	}
	i_node_table[inodeId].link_count += extraBlocks;
	fd_table[fileID].rwpointer = need;
	if (i_node_table[inodeId].link_count > 12)
	{
		write_blocks(i_node_table[inodeId].indirect_pointer, 1, &indirect_pointer_block);
	}
}

// Write the I-Node table to disk
void write_inode_table_to_disk()
{
	int inodeBlocks = (sizeof(i_node_table) / BLOCK_SIZE);
	if (sizeof(i_node_table) % BLOCK_SIZE != 0)
	{
		inodeBlocks += 1;
	}
	write_blocks(1, inodeBlocks, &i_node_table);
}

int sfs_fwrite(int fileID, const char *buf, int length)
{
	if (!is_valid_file_id(fileID))
	{
		perror("Error writing file: Invalid fileID!\n");
		return INVALID;
	}

	int inodeId = fd_table[fileID].inode_number;
	int wpointer = fd_table[fileID].rwpointer;

	if (!is_valid_inode_id(inodeId))
	{
		perror("Error writing file: Invalid directory!\n");
		return INVALID;
	}

	int need = wpointer + length;

	if (is_file_size_exceeding_limit(need))
	{
		perror("Error writing file: File size exceeds maximum file size\n");
		return INVALID;
	}

	double occupiedBlocks = i_node_table[inodeId].size / BLOCK_SIZE;
	double neededBlocks = calculate_needed_blocks(need);
	double extraBlocks = neededBlocks - occupiedBlocks;

	if (handle_indirect_pointers(inodeId, extraBlocks) == INVALID)
	{
		return INVALID;
	}

	int startBlock = fd_table[fileID].rwpointer / BLOCK_SIZE;
	int endBlock = neededBlocks;
	int offset = fd_table[fileID].rwpointer % BLOCK_SIZE;

	if (assign_free_blocks(inodeId, extraBlocks) == INVALID)
	{
		return INVALID;
	}

	void *temp = load_file_into_memory(inodeId, startBlock, endBlock);

	memcpy((temp + offset), buf, length);

	// Update the disk
	write_blocks(ROOT_DIR_BLOCK, 1, &i_node_table_bitmap);

	write_pointers_to_disk(inodeId, startBlock, endBlock, temp);
	update_inode(inodeId, need, extraBlocks, fileID);
	write_inode_table_to_disk();

	write_blocks(ROOT_DIR_BLOCK, 1, &i_node_table_bitmap);
	write_blocks(BITMAP_BLOCK, 1, &bit_map);

	free(temp);
	// Return bytes written
	return length;
}

// Calculate start and end blocks
void calculate_blocks_read(int fileID, int length, int *startBlock, int *endBlock, int *offset)
{
	*startBlock = fd_table[fileID].rwpointer / BLOCK_SIZE;
	*endBlock = (fd_table[fileID].rwpointer + length) / BLOCK_SIZE;
	*offset = fd_table[fileID].rwpointer % BLOCK_SIZE;
}

void track_read_amount(int fileID, int length, int *amount, int *end)
{
	int iNodeId = fd_table[fileID].inode_number;
	if (i_node_table[iNodeId].size < (fd_table[fileID].rwpointer + length))
	{
		*amount = i_node_table[iNodeId].size - fd_table[fileID].rwpointer;
		*end = i_node_table[iNodeId].size / BLOCK_SIZE;
		if ((i_node_table[iNodeId].size % BLOCK_SIZE) != 0)
		{
			*end = *end + 1;
		}
	}
	else
	{
		*amount = length;
		*end = (fd_table[fileID].rwpointer + length) / BLOCK_SIZE;
		if ((fd_table[fileID].rwpointer + length) % BLOCK_SIZE != 0)
		{
			*end = *end + 1;
		}
	}
}

// Check for indirect pointers and load them into memory
void *check_and_load_indirect_pointers(int iNodeId)
{
	void *temp = malloc(BLOCK_SIZE);
	if (i_node_table[iNodeId].link_count > 12)
	{
		read_blocks(i_node_table[iNodeId].indirect_pointer, 1, temp);
		memcpy(&indirect_pointer_block, temp, BLOCK_SIZE);
	}
	return temp;
}

int sfs_fread(int fileID, char *buf, int length)
{

	// Check for valid file ID
	if (!is_valid_file_id(fileID))
	{
		perror("Error reading file: Invalid fileID!\n");
		return INVALID;
	}

	int iNodeId = fd_table[fileID].inode_number;
	int rpointer = fd_table[fileID].rwpointer;
	if (iNodeId == INVALID)
	{
		perror("Error reading file: Invalid directory!\n");
		return INVALID;
	}

	int startBlock, endBlock, offset;
	calculate_blocks_read(fileID, length, &startBlock, &endBlock, &offset);

	int amount, end;
	track_read_amount(fileID, length, &amount, &end);

	// Check for indirect pointers
	void *temp1 = check_and_load_indirect_pointers(iNodeId);
	void *temp2 = load_file_into_memory(iNodeId, startBlock, end);

	fd_table[fileID].rwpointer += amount;
	memcpy(buf, (temp2 + offset), amount);

	free(temp2);
	free(temp1);

	return amount;
}

// Check if location is within file size
int check_location_within_file_size(int fileID, int loc)
{
	if (i_node_table[fd_table[fileID].inode_number].size < loc)
	{
		perror("Error seeking!");
		return INVALID;
	}
	return 0;
}

// seek to the location from beginning
int sfs_fseek(int fileID, int loc)
{
	if (check_location_within_file_size(fileID, loc) == INVALID)
	{
		return INVALID;
	}

	// Write always continues from the end of the file
	fd_table[fileID].rwpointer = loc;
	return 0;
}

// Free up the bitmap
void free_up_bitmap(int iNodeId, void *temp)
{
	for (int i = 0; i < i_node_table[iNodeId].link_count && i < 12; i++)
	{
		remove_index_bit(i_node_table[iNodeId].direct_p[i]);
	}

	// Check for indirect pointers
	if (i_node_table[iNodeId].link_count > 12)
	{
		read_blocks(i_node_table[iNodeId].indirect_pointer, 1, temp);
		memcpy(&indirect_pointer_block, temp, BLOCK_SIZE);

		// Free the bitmap
		for (int i = 12; i < i_node_table[iNodeId].link_count; i++)
		{
			remove_index_bit(indirect_pointer_block[i - 12]);
		}
	}
}

// Remove I-Node contents
void remove_inode_contents(int iNodeId)
{
	i_node_table_bitmap[iNodeId] = 0;
	i_node_table[iNodeId].mode = INVALID;
	i_node_table[iNodeId].link_count = INVALID;
	i_node_table[iNodeId].uid = INVALID;
	i_node_table[iNodeId].gid = INVALID;
	i_node_table[iNodeId].size = INVALID;
	i_node_table[iNodeId].indirect_pointer = INVALID;
	i_node_table[iNodeId].uid = INVALID;

	// Similarly assign I-Node pointers to be INVALID
	for (int j = 0; j < 12; j++)
	{
		i_node_table[iNodeId].direct_p[j] = INVALID;
	}
}

// Remove file from root directory
void remove_file_from_root_dir(char *file)
{
	for (int i = 0; i < NUM_OF_INODES; i++)
	{
		if (strcmp(root_dir[i].file_name, file) == 0)
		{
			root_dir[i].i_node = INVALID;
			for (int j = 0; j < MAX_FILE_NAME; j++)
			{
				root_dir[i].file_name[0] = '0';
			}
			break;
		}
	}
}

int sfs_remove(char *file)
{
	void *temp = malloc(BLOCK_SIZE);
	int iNodeId = get_directory_inode(file);
	if (iNodeId > 0)
	{
		free_up_bitmap(iNodeId, temp);
		remove_inode_contents(iNodeId);
		remove_file_from_root_dir(file);

		i_node_table[0].size -= 1;

		return 0;
	}
	else
	{
		perror("Error removing file: File does not exist!\n");
		return INVALID;
	}
}