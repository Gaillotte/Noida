VERSION 2


f
f
f
f
f
f
f
f
f
f
// Wearing.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <time.h>


typedef enum {

	FREE=1,		// Free and erase page -> +1 in endurance due to Erase
	RECYCLE,	// Put in RECYCLE when the value is marked as Dirty = Move to another page 
	USED		// Data Present and Valid 

} PAGE_TYPE;


//	DEFINE 
//////////////////////////////////////////////////////////////////////////////////////

// DEFINE WEARING FACTOR
// ***************************
#define	WEARING_FACTOR	2			// FACTOR in MEMORY between Used and spare for the wearing 


// DEFINE VIRTUAL MEM
//***********************
#define	VIRTUAL_SIZE_PAGE			2										// SIZE of Block
#define	VIRTUAL_SIZE_BYTES			84										// Total Size of Virtual memory in Bytes 
#define	VIRTUAL_NBR_PAGE			(VIRTUAL_SIZE_BYTES/VIRTUAL_SIZE_PAGE)	// Total number of blocks allocated for Virtual Memory

// DEFINE PHYSICAL FLASH
//*************************************
#define	WEARING_SIZE_PAGE			VIRTUAL_SIZE_PAGE						// Size of Physical block = Size of Virtual blocks 
#define	WEARING_NBR_PAGE_SECTOR		14										// Number of blocks per sector 
#define	WEARING_NBR_SECTOR_MEMORY	(WEARING_FACTOR*VIRTUAL_SIZE_BYTES/VIRTUAL_SIZE_PAGE/WEARING_NBR_PAGE_SECTOR)	// Total Number of sectors in physical memory with WL 

// Modelization of the memory erosion 
//*************************************
#define WEARING_STATIC				15	// Fixed blocks in the memory ( applets / constants ... )
#define WEARING_HSM					12	// NBR of PAGEs HSM with extended endurance requested 
#define WEARING_NSM					15	// Normal endurance in nbr of pages 

// Debug feature 
// *************************************
#define _TRACE

#ifdef _TRACE
	#define TRACE(X) // printf X
#elif
	#define	TRACE(X)
#endif // _TRACE


// TYPES AND STRCUTURE 
// **************************


// VIRTUAL MEMORY DEFINITION 
//**************************
typedef struct Virtual_Page{

	unsigned int	Physical_Sector;			// A virtual page is translated into a physical page and sector on each update virutal will move in physical memory 
	unsigned int	Physical_Page;				// A virtual page is translated into a physical page and sector on each update virutal will move in physical memory
	unsigned int	Writing;					// Information about the number of writes into the block
	unsigned char	VData[VIRTUAL_SIZE_PAGE];	// Image of the data 

} Virtual_Page;

typedef struct Virtual_Memory{					// Virtual memory is a set of Virtual pages ( id blocks ) 
	Virtual_Page VPages[VIRTUAL_NBR_PAGE];		//  
	unsigned	int	Endurance;					// Number of Erase (?) 
} Virtual_Memory;



// PHYSICAL MEMORY DEFINITION 
//***************************

// Each physical page will be made of 
//	Header : virtual page + Type of page ( FREE / ALLOCATED / RECYCLED )
//	Data 
typedef struct Wearing_PageHead{

	PAGE_TYPE		Type;				// FREE / ALLOCATED / RECYCLED
	unsigned int	Virtual;			// Which virtual page is stored in this physical block, only valid if Type = Allocated otherwise data not valid
} Wearing_PageHead;


// PAGE = HEAD + DATA
//***************************
typedef struct Wearing_Page{
	Wearing_PageHead	Page_Head;
	unsigned char	Data[WEARING_SIZE_PAGE]; 
} Wearing_Page;

// SECTOR = SET OF Physical pages ( WEARING_NBR_PAGE_SECTOR ) 
typedef struct Wearing_Sector{

	unsigned int	Endurance;							// Number of erase 
	Wearing_Page	Page[WEARING_NBR_PAGE_SECTOR];		// List of physical pages in that sector 
	// We don't consider loss of memory 
} Wearing_Sector;

// MEMORY = SET OF SECTOR								
//***************************
typedef struct Wearing_Memory{

	Wearing_Sector	Sector[WEARING_NBR_SECTOR_MEMORY]; 
	unsigned int	Endurance;							// Number of erase

	unsigned int	MemNbrDirty;						// Total number of Dirty Sectors 
	unsigned int	MemNbrFree;							// Total Number of Free Sectors 
	unsigned int	MemNbrUsed;							// Total Number of Used sectors 

} Wearing_Memory;


///////////////////////////////////////////
// Global Variables 

Wearing_Memory	gPhysical_Flash;
Virtual_Memory	gVirtual_Flash;
int				gCurrentWorkingSector = -1;

// End Global Variables 
///////////////////////////////////////////


//////////////////////////
//			CODE		//
//////////////////////////


// PRINT VIRTUAL PAGE   
void Print_Virtual_Page(Virtual_Page *ptVPage)
{
	unsigned short i;

	for(i=0;i<VIRTUAL_SIZE_PAGE;i++)
			printf("%02X ",(*ptVPage).VData[i]);

}

// PRINT VIRTUAL MEMORY
void Print_Virtual_Memory(Virtual_Memory *ptVMemory)
{

	unsigned short i;

	for(i=0;i<VIRTUAL_NBR_PAGE;i++)
	{
		printf("P[%02X,%02d,%02d,%d]",i,(*ptVMemory).VPages[i].Physical_Sector,(*ptVMemory).VPages[i].Physical_Page,(*ptVMemory).VPages[i].Writing);
		Print_Virtual_Page(&(*ptVMemory).VPages[i]);
		printf("\n");
	}
}

// Init VIRTUAL PAGE   
void Init_Virtual_Page(Virtual_Page *ptVPage)
{
	unsigned short i;

	(*ptVPage).Physical_Page=0xFFFFFFFF;
	(*ptVPage).Physical_Sector=0xFFFFFFFF;
	(*ptVPage).Writing=0;

	for(i=0;i<VIRTUAL_SIZE_PAGE;i++)
			(*ptVPage).VData[i]=0;

}

// Init VIRTUAL MEMORY
void Init_Virtual_Memory(Virtual_Memory *ptVMemory)
{
	unsigned short i;

	for(i=0;i<VIRTUAL_NBR_PAGE;i++)
		Init_Virtual_Page(&(*ptVMemory).VPages[i]);

	(*ptVMemory).Endurance=0;

}



// PRINT HEAD  
// (x,y,z) : 
void Print_Head(Wearing_PageHead *ptHead)
{
	printf("H(%01X,%02X)",(*ptHead).Type,(*ptHead).Virtual);
}

// PRINT PAGE 
// (x) : print Type of page 
// <x> : print Endurance 
// x| :Data of the page 
// **********************************
void Print_Page(Wearing_Page *ptPage)
{
	unsigned short i;

	Print_Head(&(*ptPage).Page_Head);

		for(i=0;i<WEARING_SIZE_PAGE;i++)
			printf("%02X ",(*ptPage).Data[i]);

}

// PRINT SECTOR 
// [x] : print Page number  
// **********************************
void Print_Sector(Wearing_Sector *ptSector)
{
	unsigned short i;

	
	for(i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
	{
		printf("P[%02X]",i);
		Print_Page(&(*ptSector).Page[i]);
	}

}

// PRINT SECTOR 
// {x} : print Sector number  
// **********************************

void Print_Physical_Memory(Wearing_Memory	*ptMemory)
{
	unsigned short i;

	printf("\n");

	printf("\tVIRTUAL MEMORY\n");
	printf("Size Virtual %4d\n",VIRTUAL_SIZE_BYTES);
	printf("Size Block Virtuak %4d\n",VIRTUAL_SIZE_PAGE);
	printf("\tPHYSICAL MEMORY\n");
	printf("Flash Page Size %4d\n",WEARING_SIZE_PAGE );
	printf("Flash Nbr Page per Sector %4d\n",WEARING_NBR_PAGE_SECTOR);
	printf("Flash Nbr Sectors %4d\n",WEARING_NBR_SECTOR_MEMORY);
	
	for(i=0;i<WEARING_NBR_SECTOR_MEMORY;i++)
	{
			printf("S{%02X,%d}",i,(*ptMemory).Sector[i].Endurance);
			Print_Sector(&(*ptMemory).Sector[i]);
			printf("\n");
	}

	printf("\n");
	
}


void Init_Head(Wearing_PageHead *ptHead)
{
	(*ptHead).Type=FREE;
	(*ptHead).Virtual=0;
}

void Init_Page(Wearing_Page *ptPage)
{
	unsigned short i;

	Init_Head ( &(*ptPage).Page_Head);

	for(i=0;i<WEARING_SIZE_PAGE;i++)
		(*ptPage).Data[i]=0xFF;

	gPhysical_Flash.MemNbrFree++;
}

// Only called during defrag of a sector 
//**************************************
void Free_Page(Wearing_Page *ptPage)
{
	if (ptPage->Page_Head.Type == FREE)
	{
		TRACE(("\n ERROR : cannot erase an already erased \n"));
		exit(1);
	}
	if (ptPage->Page_Head.Type == USED)
	{
		TRACE(("\n ERROR : cannot erase a used sector \n"));
		exit(1);
	}

	Init_Page(ptPage);

	gPhysical_Flash.MemNbrDirty--;
}


// Page is copied/updated elsewhere then the page shall be marked RECYCLED 
// ***********************************************************************
void Recycle_Page(Wearing_Page *ptPage)
{
	if (ptPage->Page_Head.Type != USED)
	{
		TRACE(("\n ERROR : cannot recycle an unused block \n"));
		exit(1);
	}

	(*ptPage).Page_Head.Type=RECYCLE;
	(*ptPage).Page_Head.Virtual=0xFF;

	gPhysical_Flash.MemNbrDirty++;
	gPhysical_Flash.MemNbrUsed--;
}


void Init_Sector(Wearing_Sector *ptSector)
{
	unsigned short i;

	(*ptSector).Endurance=0;
	for(i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
	{
		Init_Page(&(*ptSector).Page[i]);
	}

}


void Init_Physical_Memory(Wearing_Memory *ptMemory)
{
	unsigned short i;
	(*ptMemory).Endurance=0;

	(*ptMemory).MemNbrDirty =	0;
	(*ptMemory).MemNbrFree =	0;
	(*ptMemory).MemNbrUsed =	0;

	for(i=0;i<WEARING_NBR_SECTOR_MEMORY;i++)
	{
		Init_Sector(&(*ptMemory).Sector[i]);
	}

}
void Delete_Sector(Wearing_Sector *ptSector)
{
	unsigned short i;

	// BACKUP 
		// No need to backup on PC 		
	(*ptSector).Endurance++;
	for(i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
	{
		Init_Page(&(*ptSector).Page[i]);
	}

}

int	Find_Sector_with_Free_Page()
{
	unsigned int SectorID;
	unsigned int lSector;
	unsigned int i;

	unsigned int NbrSectWithFree=0;

	unsigned short SectWithFree[WEARING_NBR_SECTOR_MEMORY];	

	// First Loop to identify the Sectors with Free
	// improvment if status per sector managed on the fly 
	///////////////////////////////////////////////////////////////

	// Zeroize 
	memset(SectWithFree,0,sizeof(unsigned short)*WEARING_NBR_SECTOR_MEMORY);

	for (SectorID=0;SectorID<WEARING_NBR_SECTOR_MEMORY;SectorID++)
	{
		for (i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
		{
			if (gPhysical_Flash.Sector[SectorID].Page[i].Page_Head.Type==FREE)
			{
				if (SectWithFree[SectorID]==0)
					NbrSectWithFree++;
				SectWithFree[SectorID]++;
				return SectorID;
			}
		}
	}

	// srand((unsigned int)time(0));
	
	if (NbrSectWithFree!=0)
	{
		// Randomly choose the Free to use 
		
		lSector = rand()%NbrSectWithFree;

		TRACE(("\n Find Sector with Free %d sectors = %d\n",NbrSectWithFree,lSector));
		TRACE(("\n FREE lSector = %d\n",lSector));

		NbrSectWithFree=0; // Reset counter
		// Second loop 
		for (SectorID=0;SectorID<WEARING_NBR_SECTOR_MEMORY;SectorID++)
		{
			if (SectWithFree[SectorID]!=0)
			{
				// IMPROVMENT : the choice of the sector shall be on the one with the highest number of Recycle ? 
				
				NbrSectWithFree++;
				if (NbrSectWithFree==lSector)
				{
						if (lSector==(WEARING_NBR_SECTOR_MEMORY-1))
							TRACE(("\nLast Sector reached\n"));
						return SectorID;
				}
			}
		}
	}

	return -1; 
}

int	Find_Sector_with_Full_Recycle_Page()
{
	unsigned int SectorID;
	unsigned int lSector;
	unsigned int i;

	unsigned int NbrSectWithFullRecycle=0;

	unsigned short SectWithRecycle[WEARING_NBR_SECTOR_MEMORY];	// First loop to count the number of Recycle in the sector 

	// First Loop to identify the Sectors with Recycle 
	// improvment if status per sector managed on the fly 
	///////////////////////////////////////////////////////////////

	// Zeroize 
	memset(SectWithRecycle,0,sizeof(unsigned short)*WEARING_NBR_SECTOR_MEMORY);

	for (SectorID=0;SectorID<WEARING_NBR_SECTOR_MEMORY;SectorID++)
	{
		for (i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
		{
			if (gPhysical_Flash.Sector[SectorID].Page[i].Page_Head.Type!=RECYCLE)
				break;
		}
		if (i==WEARING_NBR_PAGE_SECTOR)
		{
			// Full sector is RECYCLE 
			SectWithRecycle[SectorID]=1;
			NbrSectWithFullRecycle++;
		}
	}

	if (NbrSectWithFullRecycle!=0)
		lSector=rand()%NbrSectWithFullRecycle;
	else
		return -1;

	NbrSectWithFullRecycle=0;

	for (SectorID=0;SectorID<WEARING_NBR_SECTOR_MEMORY;SectorID++)
	{
		if (SectWithRecycle[SectorID]==1)
		{
			if (lSector==NbrSectWithFullRecycle)
			{
				// printf("Full Sector Recycle %d\n",SectorID);
				return SectorID;
			}
			NbrSectWithFullRecycle++;
		}
	}
	
	return -1; 
}



int	Find_Sector_with_Recycle_Page()
{
	unsigned int SectorID;
	unsigned int lSector;
	unsigned int i;

	unsigned int NbrSectWithRecycle=0;

	unsigned short SectWithRecycle[WEARING_NBR_SECTOR_MEMORY];	// First loop to count the number of Recycle in the sector 

	// First Loop to identify the Sectors with Recycle 
	// improvment if status per sector managed on the fly 
	///////////////////////////////////////////////////////////////

	// Zeroize 
	memset(SectWithRecycle,0,sizeof(unsigned short)*WEARING_NBR_SECTOR_MEMORY);

	for (SectorID=0;SectorID<WEARING_NBR_SECTOR_MEMORY;SectorID++)
	{
		for (i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
		{
			if (gPhysical_Flash.Sector[SectorID].Page[i].Page_Head.Type==RECYCLE)
			{
				if (SectWithRecycle[SectorID]==0)
					NbrSectWithRecycle++;
				SectWithRecycle[SectorID]++;
			}
		}
	}

	// srand((unsigned int)time(0));
	
	if (NbrSectWithRecycle!=0)
	{
		// Randomly choose the Recycle to use 
			lSector = rand() % NbrSectWithRecycle;
		//lSector =0;
		
		TRACE(("\n Find Sector with Recycle %d sectors = %d\n",NbrSectWithRecycle,lSector));
		TRACE(("\n RECYCLE lSector = %d\n",lSector));

		NbrSectWithRecycle=0; // Reset counter
		// Second loop 
		for (SectorID=0;SectorID<WEARING_NBR_SECTOR_MEMORY;SectorID++)
		{
			if (SectWithRecycle[SectorID]!=0)
			{
				// IMPROVMENT : the choice of the sector shall be on the one with the highest number of Recycle ? 
				if (NbrSectWithRecycle==lSector)
				{
						if (lSector==(WEARING_NBR_SECTOR_MEMORY-1))
							TRACE(("\nLast Sector reached\n"));
						return SectorID;
				}
				NbrSectWithRecycle++;
			}
			
		}
	}

	return -1; 
}

int	DefragSector0(unsigned int Idx_Sector)
{
	unsigned int i,j;
	unsigned int Idx_Recyle=-1;
	BOOLEAN	Swap;
	

		for (i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
		{
			if (gPhysical_Flash.Sector[Idx_Sector].Page[i].Page_Head.Type==RECYCLE)
			{
				// memorize the fact that at least one is recycle 
				Idx_Recyle = i;
				Swap = FALSE;  // All remaining are RECYCLE
				for (j=i+1;j<WEARING_NBR_PAGE_SECTOR;j++)
				{
				if (gPhysical_Flash.Sector[Idx_Sector].Page[j].Page_Head.Type==USED)
					{
						Swap=TRUE;	// Memorize one swap done 
						// Copy USED to RECYCLE
						memcpy(&gPhysical_Flash.Sector[Idx_Sector].Page[i],&gPhysical_Flash.Sector[Idx_Sector].Page[j],sizeof(Wearing_Page));
						// Clear Origin 
						Init_Page(&gPhysical_Flash.Sector[Idx_Sector].Page[j]);
					}	
				}
				if (Swap==FALSE)
				{
					// No Swap = no more Used page = Free all remaining pages 
					for (j=i;j<WEARING_NBR_PAGE_SECTOR;j++)
						Init_Page(&gPhysical_Flash.Sector[Idx_Sector].Page[j]);
				}

			}
		}

		if (Idx_Recyle==-1)
			return -1;

		// Increment Endurance of Sector 
		gPhysical_Flash.Sector[Idx_Sector].Endurance++;
	
	return 0; 
}

int	DefragSector(int Idx_Sector)
{
	unsigned int i;
	unsigned int Idx_Recyle=-1;

	if (Idx_Sector==-1)
		return -1;

		for (i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
		{
			if (gPhysical_Flash.Sector[Idx_Sector].Page[i].Page_Head.Type==RECYCLE)
			{
				Init_Page(&gPhysical_Flash.Sector[Idx_Sector].Page[i]);
				// At least one block has been Free 
				Idx_Recyle=0;
				// CAUTION : No compactor done 
			}
		}

		// Increment Endurance of Sector 
		gPhysical_Flash.Sector[Idx_Sector].Endurance++;
		gPhysical_Flash.Endurance++;

	
	return Idx_Recyle; 
}




int	Sect_Find_Page_Free(unsigned int	Idx_Sect)
{
	unsigned int i;

	for (i=0;i<WEARING_NBR_PAGE_SECTOR;i++)
	{
		if (gPhysical_Flash.Sector[Idx_Sect].Page[i].Page_Head.Type==FREE)
			return i;
	}

	return -1; 

}

int	Page_Copy(unsigned int	Idx_VPage,unsigned int	Idx_DstSect,unsigned int	Idx_DstPage)
{

	// Copy content of VPage to Physical Page only if Dst is Free
	if (gPhysical_Flash.Sector[Idx_DstSect].Page[Idx_DstPage].Page_Head.Type==FREE)
		memcpy( gPhysical_Flash.Sector[Idx_DstSect].Page[Idx_DstPage].Data,gVirtual_Flash.VPages[Idx_VPage].VData,WEARING_SIZE_PAGE);
	else 
		return -1;

	// Mark Dst as active = USED
	gPhysical_Flash.Sector[Idx_DstSect].Page[Idx_DstPage].Page_Head.Type=USED;
	gPhysical_Flash.Sector[Idx_DstSect].Page[Idx_DstPage].Page_Head.Virtual=Idx_VPage;

	// Mark Src as inActive = RECYCLE 
	if (gVirtual_Flash.VPages[Idx_VPage].Physical_Sector!=0xFFFFFFFF)
		gPhysical_Flash.Sector[gVirtual_Flash.VPages[Idx_VPage].Physical_Sector].Page[gVirtual_Flash.VPages[Idx_VPage].Physical_Page].Page_Head.Type=RECYCLE;

	// Update Virtual PAge
	gVirtual_Flash.VPages[Idx_VPage].Physical_Sector=Idx_DstSect;
	gVirtual_Flash.VPages[Idx_VPage].Physical_Page=Idx_DstPage;
	gVirtual_Flash.VPages[Idx_VPage].Writing++;
	gVirtual_Flash.Endurance++;

	gCurrentWorkingSector = Idx_DstSect;

	return 0; 

}


// Write Src to VFlash at Offset for len 

int	WriteVMemory(unsigned int	Idx_VPage,unsigned char *BuffSrc )
{
	
	int Idx_Target_Sector;
	int Idx_Target_Sector_Free;
	int Idx_FreePg;	

	

		// Update Virtual page 
		memcpy(&gVirtual_Flash.VPages[Idx_VPage].VData[0],BuffSrc,VIRTUAL_SIZE_PAGE);

		// Is the Virtual page already mapped ?
		if (gVirtual_Flash.VPages[Idx_VPage].Physical_Sector==0xFFFFFFFF)
		{
			// No = Mapping the first time 
			// Target_Sector = 0
			Idx_Target_Sector=0;
		} 
		else
		{
			// Target Sector is the one assigned to the vPage
			Idx_Target_Sector=gVirtual_Flash.VPages[Idx_VPage].Physical_Sector;
		}

		// if no freepage in same sector than source then switch to working sector 
		Idx_FreePg = Sect_Find_Page_Free(Idx_Target_Sector);

		if (Idx_FreePg==-1)
			Idx_Target_Sector= gCurrentWorkingSector;  
	


STEP0: 
		// STEP 0 : Free Page in Target Sector ? 
		Idx_FreePg = Sect_Find_Page_Free(Idx_Target_Sector);

		if (Idx_FreePg!=-1)
		{
			// Yes Update the first free page  // Release Current Page 
			TRACE(("\n one page free in %d\n",Idx_Target_Sector));
			if (Page_Copy(Idx_VPage,Idx_Target_Sector,Idx_FreePg)!=-1)
				return 0;
			else
				return -1;
		}
		else
		{
				// No Free page in Target Sector

					// STEP 1 : Find New Target Sector with Free Page
					Idx_Target_Sector_Free=Find_Sector_with_Free_Page();
					if(Idx_Target_Sector_Free!=-1)
					{
						// Yes
						// GOTO STEP 0
						TRACE(("\n Switch to another sector with free buffers\n"));
						Idx_Target_Sector=Idx_Target_Sector_Free;
						goto STEP0;
					}
					else 
					{
						// No 
							// Defrag of Target Sector is possible
							Idx_Target_Sector = Find_Sector_with_Full_Recycle_Page();

							if (DefragSector(Idx_Target_Sector)!=-1)
							{
								// Yes 
									// GOTO STEP 0  
								TRACE(("\n DEFRAG SECTOR_0 %d\n",Idx_Target_Sector));
								goto STEP0;
							}
							else 
							{
								// No
								// Find Target Sector who can be defrag  
								Idx_Target_Sector = Find_Sector_with_Recycle_Page();
								TRACE(("\n Switch to another sector with recycle buffers %d \n",Idx_Target_Sector));

								if (Idx_Target_Sector!=-1)
								{
										// Yes
										// Defrag Target Sector 
										
										if (DefragSector(Idx_Target_Sector)!=-1)
										{
											// Yes 
											// GOTO STEP 0  
											TRACE(("\n DEFRAG SECTOR_1 %d\n",Idx_Target_Sector));
											goto STEP0;
										}
										else
										{
											// FATAL ERROR 
											printf("ERROR ERROR\n");
										}
								}
								else
								{
									// FATAL ERROR
									printf("ERROR ERROR\n");
								}
							}
					}
												
								
		}
		return 0;
}

int CheckMemory()
{
	int	i,IdxSect,IdxPage; 


	for(i=0;i<VIRTUAL_SIZE_PAGE;i++)
	{

		IdxSect =gVirtual_Flash.VPages[i].Physical_Sector;
		IdxPage =gVirtual_Flash.VPages[i].Physical_Page;

		if ( memcmp( gPhysical_Flash.Sector[IdxSect].Page[IdxPage].Data,gVirtual_Flash.VPages[i].VData,WEARING_SIZE_PAGE) !=0)
		{
			return -1;
		}
	}

	return 0;
}

void cls()

{
	HANDLE						hConsole;
	COORD						coordScreen = {0, 0};
	DWORD						cCharsWritten;
	CONSOLE_SCREEN_BUFFER_INFO	csbi;
	DWORD						dwConSize;


  	 hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

      // Get the number of character cells in the current buffer
      if(!GetConsoleScreenBufferInfo(hConsole, &csbi))
		  return;

      dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

	  // Fill the entire screen with blanks
      if(!FillConsoleOutputCharacter(hConsole, (WCHAR)' ', dwConSize, coordScreen, &cCharsWritten))
            return;

      // Get the current text attribute.
      if(!GetConsoleScreenBufferInfo(hConsole, &csbi))
            return;

      // Set the buffer's attributes accordingly.
      if(!FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten))
            return;

      // Put the cursor at its home coordinates.
      SetConsoleCursorPosition(hConsole, coordScreen);

}




int _tmain(int argc, _TCHAR* argv[])
{
	unsigned int i,Loop,VirtualPage;
	unsigned char Buff[2];
	unsigned int	FillIdx=0;
	unsigned int	LoopWrite[10];



	printf("**************************************** \n");
	printf("     Wearing Test \n");
	printf("**************************************** \n");

	LoopWrite[0]=1000;
	LoopWrite[1]=10000;
	LoopWrite[2]=50000;
	LoopWrite[3]=100000;
	LoopWrite[4]=1000000;
	LoopWrite[5]=10000000;
	LoopWrite[6]=20000000;
	LoopWrite[7]=30000000;
	LoopWrite[8]=50000000;
	LoopWrite[9]=100000000;



	for (Loop=1;Loop<10;Loop++)
	{
			Init_Physical_Memory(&gPhysical_Flash);
			Init_Virtual_Memory(&gVirtual_Flash);


			srand((unsigned int)time(0));

			// Fill the memory first time linear allocation 
			for (i=0;i<VIRTUAL_NBR_PAGE;i++)
			{
				Buff[0]= 0;
				Buff[1]= 0;
				WriteVMemory(i ,Buff);
			}

			

			// Fill the memory second time with random access to fill the wearing memory = Goal avoid static behaviour 
			/*srand(time(NULL));
			memset(gDataFill,0x00,VIRTUAL_NBR_PAGE);
			for (i=0;i<VIRTUAL_NBR_PAGE;i++)
			{
				Buff[0]=rand() % 0xFF;
				Buff[1]=rand() % 0xFF;
				FillIdx = rand()%VIRTUAL_NBR_PAGE;
				if (gDataFill[FillIdx]==0)
				{
					// Each page rewritten only once randomly 
					gDataFill[FillIdx]++;
					WriteVMemory( FillIdx ,Buff);
				}
				else
				{
					i--;
				}
			}*/
			/*
			// Fill the memory third time with random access to fill the wearing memory = Goal avoid static behaviour 
			srand(time(NULL));
			memset(gDataFill,0x00,VIRTUAL_NBR_PAGE);
			for (i=0;i<VIRTUAL_NBR_PAGE;i++)
			{
				Buff[0]=rand() % 0xFF;
				Buff[1]=rand() % 0xFF;
				FillIdx = rand()%VIRTUAL_NBR_PAGE;
				if (gDataFill[FillIdx]==0)
				{
					// Each page rewritten only once randomly 
					gDataFill[FillIdx]++;
					WriteVMemory( FillIdx ,Buff);
				}
				else
				{
					i--;
				}
			}*/


		/* printf("\n ALLOCATION  \n");

		Print_Physical_Memory(&gPhysical_Flash) ;
		printf("\n");
		Print_Virtual_Memory(&gVirtual_Flash);

		getchar(); */

			srand(time(NULL));

			 for (i=0;i<10000000;i++)
			//for (i=0;i<LoopWrite[Loop];i++)
			{
				
				Buff[0]=rand() % 0xFF;
				Buff[1]=rand() % 0xFF;

				if ((i%(25+1))!=0)
				{
					VirtualPage = (rand() % WEARING_HSM)+WEARING_STATIC;
					WriteVMemory(VirtualPage ,Buff);
				}
				else 
				{
					VirtualPage = ( rand() % WEARING_NSM ) + WEARING_HSM + WEARING_STATIC ;				
					WriteVMemory(VirtualPage ,Buff);
				}


			}

		if (CheckMemory()!=-1)
		{
			Print_Physical_Memory(&gPhysical_Flash) ;
			printf("\n");
			Print_Virtual_Memory(&gVirtual_Flash);

			printf(" Loop %d Writings %d Sector Erase %d Average %f\n",Loop,gVirtual_Flash.Endurance,gPhysical_Flash.Endurance,(float)gVirtual_Flash.Endurance/(float)gPhysical_Flash.Endurance);

			getchar();

		}
		else
		{
			printf("ERROR CHECK SOMETHING WENT WRONG\n");
			getchar();
			exit(1);
		}
				
	}

	getchar();


		Print_Physical_Memory(&gPhysical_Flash) ;
		printf("\n");
		Print_Virtual_Memory(&gVirtual_Flash);
		getchar();

		cls();

	return 0;
}



