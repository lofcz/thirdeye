SECTIONS
{
    /DISCARD/ :
    {
        *(.rdata$zzz)
        *(.comment)
        *(.comment.*)
        *(.note)
        *(.note.*)
    }
}
INSERT AFTER .rdata;
