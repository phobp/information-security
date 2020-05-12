/*-------------------------------------------------------------------------------
Written By: 
     1- Dr. Mohamed Aboutabl
     2- Brendan Pho and Wesley Llamas (GROUP 7)
 
Submitted on: September 16, 2019

This code complies with the JMU Honor Code.
-------------------------------------------------------------------------------*/
#include "wrappers.h"

///--------------------------------------------------------------------------
pid_t Fork(void) 
{
    pid_t pid;

    if ( (pid = fork() ) < 0)
	    perror("Fork error");
    return pid;
}

//--------------------------------------------------------------------------
int  Pipe( int fdArr[2] ) 
{
	int result ;
	
	result = pipe( fdArr ) ;
	if ( result == -1 ) 
    {
        perror( "Pipe failed" ) ;
        exit(-1) ;		;
    }
    return result ;    
}

