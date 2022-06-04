#ifndef CRC_HPP
#define CRC_HPP
#include <array>
#include <iostream>

/*
Reference websites
    http://www.ross.net/crc/crcpaper.html
    https://cs.fit.edu/code/svn/cse2410f13team7/wireshark/wsutil/crc16.c
    http://www.ross.net/crc/download/crc_v3.txt
*/

#define TRUE    1
#define FALSE   0


#define BITMASK(X) (1L << (X))

#define TB_WIDTH  2
#define TB_POLY   0x5935 
#define TB_REVER  FALSE  

constexpr ulong reflect (ulong v, int b)
/* Returns the value v with the bottom b [0,32] bits reflected. */
/* Example: reflect(0x3e23L,3) == 0x3e26                        */
{
 int   i=0;
 ulong t = v;
 for (i=0; i<b; i++)
   {
    if (t & 1L)
       v|=  BITMASK((b-1)-i);
    else
       v&= ~BITMASK((b-1)-i);
    t>>=1;
   }
 return v;
}

// CRC Model
struct cm_t
  {
   int   cm_width;   /* Parameter: Width in bits [8,32].       */
   ulong cm_poly;    /* Parameter: The algorithm's polynomial. */
   ulong cm_init;    /* Parameter: Initial register value.     */
   bool  cm_refin;   /* Parameter: Reflect input bytes?        */
   bool  cm_refot;   /* Parameter: Reflect output CRC?         */
   ulong cm_xorot;   /* Parameter: XOR this to output CRC.     */

   ulong cm_reg;     /* Context: Context during execution.     */

   constexpr cm_t() : cm_width(0), cm_poly(0), cm_init(0), cm_refin(0), cm_refot(0), cm_xorot(0), cm_reg(0){}
  };


typedef cm_t *p_cm_t;

constexpr ulong widmask (p_cm_t p_cm)
/* Returns a longword whose value is (2^p_cm->cm_width)-1.     */
/* The trick is to do this portably (e.g. without doing <<32). */
{
 return (((1L<<(p_cm->cm_width-1))-1L)<<1)|1L;
}


constexpr int cm_tab(p_cm_t p_cm, int index)
{
 int   i=0;
 ulong r=0;
 ulong topbit = BITMASK(p_cm->cm_width-1);
 ulong inbyte = (ulong) index;

 if (p_cm->cm_refin) inbyte = reflect(inbyte,8);
 r = inbyte << (p_cm->cm_width-8);
 for (i=0; i<8; i++)
    if (r & topbit)
       r = (r << 1) ^ p_cm->cm_poly;
    else
       r<<=1;
 if (p_cm->cm_refin) r = reflect(r,p_cm->cm_width);
 return r & widmask(p_cm);
}

constexpr auto _GetTable() -> std::array<int,256>
{
    cm_t cm;

    cm.cm_width = TB_WIDTH*8;
    cm.cm_poly  = TB_POLY;
    cm.cm_refin = TB_REVER;

    std::array<int,256> table{};
    for(auto i=0; i<256; i++)
    {
        table[i] = cm_tab(&cm,i);
    }

    return table;
}


auto& GetTable()
{
    static constexpr std::array<int,256> table = _GetTable();
    return table;
}


// int main()
// {
//     auto& table = GetTable();
//     for(auto i=0; i < 8; i++)
//         std::cout << "0x" << std::hex << table[i] << ", ";
// }


#endif // #ifndef CRC_HPP