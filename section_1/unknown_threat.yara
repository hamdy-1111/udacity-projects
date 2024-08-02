rule UnknownThreat
{
    meta:
        description = "Detects the unique malware may affect other servers!!"
        author = "noopsaibot"  //noor eldin Elmenshawi
        date = "2024-07-25"
        version = "1.0"

    strings:
        $string1 = "
St15time_put_bynameIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEE
St8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE
St15time_get_bynameIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE
St15messages_bynameIcE
St18__moneypunct_cacheIcLb0EE
St18__moneypunct_cacheIcLb1EE
St16__numpunct_cacheIcE
St21__ctype_abstract_baseIcE
basic_string::_M_create
basic_string::_M_replace
string::string
N10__cxxabiv117__class_type_infoE
N10__cxxabiv121__vmi_class_type_infoE
terminate called recursively
terminate called after throwing an instance of '
terminate called without an active exception
  what():  
std::bad_typeid
St10bad_typeid
N10__cxxabiv120__si_class_type_infoE
St9type_info
std::bad_cast
St8bad_cast
pure virtual method called
deleted virtual method called
locale::_S_normalize_category category not found
locale::_Impl::_M_replace_facet
NSt6locale5facetE
January
February
March
April
June
July
August
September
October
November
December
-+xX0123456789abcdef0123456789ABCDEF
-+xX0123456789abcdefABCDEF
-0123456789
AKST
St16__numpunct_cacheIwE
locale::facet::_S_create_c_locale name not valid
LC_CTYPE
LC_NUMERIC
LC_TIME
LC_COLLATE
LC_MONETARY
LC_MESSAGES
St7codecvtIcc11__mbstate_tE
St7codecvtIwc11__mbstate_tE
St18__moneypunct_cacheIwLb1EE
St18__moneypunct_cacheIwLb0EE
St11logic_error
St12domain_error
St16invalid_argument
St12length_error
St12out_of_range
St13runtime_error
St11range_error
St14overflow_error
St15underflow_error
NSt8ios_base7failureE
cannot create shim for unknown locale::facet
uninitialized __any_string
*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_112collate_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE
*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_113messages_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_112collate_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE
*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_113messages_shimIwEE
NSt6locale5facet6__shimE
*NSt13__facet_shims12_GLOBAL__N_113time_get_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_113time_get_shimIwEE
St15basic_streambufIcSt11char_traitsIcEE
St15basic_streambufIwSt11char_traitsIwEE
basic_ios::clear
St9basic_iosIcSt11char_traitsIcEE
St9basic_iosIwSt11char_traitsIwEE
St7collateIwE
St14collate_bynameIwE
St21__ctype_abstract_baseIwE
St8numpunctIwE
St15numpunct_bynameIwE
St7num_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE
St7num_putIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEE
St17__timepunct_cacheIwE
St11__timepunctIwE
St10moneypunctIwLb1EE
St10moneypunctIwLb0EE
St8messagesIwE
St23__codecvt_abstract_baseIwc11__mbstate_tE
St14codecvt_bynameIwc11__mbstate_tE
St17moneypunct_bynameIwLb0EE
St17moneypunct_bynameIwLb1EE
St9money_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE
St9money_putIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEE
St8time_putIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEE
St15time_put_bynameIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEE
St8time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE
St15time_get_bynameIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE
St15messages_bynameIwE
St13basic_ostreamIwSt11char_traitsIwEE
NSt7__cxx117collateIwEE
NSt7__cxx1114collate_bynameIwEE
NSt7__cxx118numpunctIwEE
NSt7__cxx1115numpunct_bynameIwEE
NSt7__cxx1110moneypunctIwLb1EEE
NSt7__cxx1110moneypunctIwLb0EEE
NSt7__cxx118messagesIwEE
NSt7__cxx1117moneypunct_bynameIwLb0EEE
NSt7__cxx1117moneypunct_bynameIwLb1EEE
NSt7__cxx119money_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEE
NSt7__cxx119money_putIwSt19ostreambuf_iteratorIwSt11char_traitsIwEEEE
NSt7__cxx118time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEE
NSt7__cxx1115time_get_bynameIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEE
NSt7__cxx1115messages_bynameIwEE
ios_base::_M_grow_words is not valid
ios_base::_M_grow_words allocation failed
St8ios_base
St5ctypeIcE
St5ctypeIwE
St12ctype_bynameIwE
St13basic_istreamIwSt11char_traitsIwEE
St23__codecvt_abstract_baseIDsc11__mbstate_tE
St7codecvtIDsc11__mbstate_tE
St23__codecvt_abstract_baseIDic11__mbstate_tE
St7codecvtIDic11__mbstate_tE
St19__codecvt_utf8_baseIDsE
St20__codecvt_utf16_baseIDsE
St25__codecvt_utf8_utf16_baseIDsE
St19__codecvt_utf8_baseIDiE
St20__codecvt_utf16_baseIDiE
St25__codecvt_utf8_utf16_baseIDiE
St19__codecvt_utf8_baseIwE
St20__codecvt_utf16_baseIwE
St25__codecvt_utf8_utf16_baseIwE
cntrl
punct
St12ctype_bynameIcE
*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_112collate_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE
*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_113messages_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_113numpunct_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_112collate_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE
*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE
*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_113messages_shimIwEE
*NSt13__facet_shims12_GLOBAL__N_113time_get_shimIcEE
*NSt13__facet_shims12_GLOBAL__N_113time_get_shimIwEE
NSt7__cxx117collateIcEE
NSt7__cxx1114collate_bynameIcEE
NSt7__cxx118numpunctIcEE
NSt7__cxx1115numpunct_bynameIcEE
NSt7__cxx1110moneypunctIcLb1EEE
NSt7__cxx1110moneypunctIcLb0EEE
NSt7__cxx118messagesIcEE
NSt7__cxx1117moneypunct_bynameIcLb0EEE
NSt7__cxx1117moneypunct_bynameIcLb1EEE
NSt7__cxx119money_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEE
NSt7__cxx119money_putIcSt19ostreambuf_iteratorIcSt11char_traitsIcEEEE
NSt7__cxx118time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEE
NSt7__cxx1115time_get_bynameIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEE
NSt7__cxx1115messages_bynameIcEE
_GLOBAL_
(anonymous namespace)
[abi:
{default arg#
JArray
VTT for 
construction vtable for 
-in-
typeinfo for 
typeinfo name for 
typeinfo fn for 
non-virtual thunk to 
covariant return thunk to 
java Class for 
guard variable for 
TLS init function for 
TLS wrapper function for 
reference temporary #
hidden alias for 
non-transaction clone for 
_Sat 
_Accum
_Fract
operator
operator 
new 
java resource 
decltype (
this
{parm#
global constructors keyed to 
global destructors keyed to 
{lambda(
{unnamed type#
 [clone 
 restrict
 volatile
 const
complex 
imaginary 
 __vector(
string literal
auto
std::allocator
std::basic_string
std::string
std::basic_string<char, std::char_traits<char>, std::allocator<char> >
std::istream
std::basic_istream<char, std::char_traits<char> >
basic_istream
std::ostream
std::basic_ostream<char, std::char_traits<char> >
basic_ostream
std::iostream
std::basic_iostream<char, std::char_traits<char> >
basic_iostream
alignof 
const_cast
delete[] 
dynamic_cast
delete 
operator"" 
new[]
reinterpret_cast
static_cast
sizeof 
throw
throw 
bool
boolean
byte
long double
float
__float128
unsigned char
unsigned int
unsigned
unsigned long
unsigned __int128
unsigned short
void
wchar_t
unsigned long long
decimal32
decimal64
decimal128
half
char16_t
char32_t
decltype(nullptr)
alnum
alpha
blank
cntrl
digit
graph
lower
print
punct
space
upper
xdigit
$%&'()*+
23456789
<=>?@A
JKLM
TUVW
[\]^_`ab
2!N!
!`,a,b,k
r,s,u,v,~,?
,0/g,
/dev/null
Illegal byte sequence
Domain error
Result not representable
Not a tty
Permission denied
Operation not permitted
No such file or directory
No such process
File exists
Value too large for data type
No space left on device
Out of memory
Resource busy
Interrupted system call
Resource temporarily unavailable
Invalid seek
Cross-device link
Read-only file system
Directory not empty
Connection reset by peer
Operation timed out
Connection refused
Host is down
Host is unreachable
Address in use
Broken pipe
I/O error
No such device or address
Block device required
No such device
Not a directory
Is a directory
Text file busy
Exec format error
Invalid argument
Argument list too long
Symbolic link loop
Filename too long
Too many open files in system
No file descriptors available
Bad file descriptor
No child process
Bad address
File too large
Too many links
No locks available
Resource deadlock would occur
State not recoverable
Previous owner died
Operation canceled
Function not implemented
No message of desired type
Identifier removed
Device not a stream
No data available
Device timeout
Out of streams resources
Link has been severed
Protocol error
Bad message
File descriptor in bad state
Not a socket
Destination address required
Message too large
Protocol wrong type for socket
Protocol not available
Protocol not supported
Socket type not supported
Not supported
Protocol family not supported
Address family not supported by protocol
Address not available
Network is down
Network unreachable
Connection reset by network
Connection aborted
No buffer space available
Socket is connected
Socket not connected
Cannot send after socket shutdown
Operation already in progress
Operation in progress
Stale file handle
Remote I/O error
Quota exceeded
No medium found
Wrong medium type
No error information
'hnopqb 
}&*+<=>?CGJMXYZ[\]^_`acdefgijklrstyz{|
/proc/self/exe
: unrecognized option: 
: option requires an argument: 
: option is ambiguous: 
: option does not take an argument: 
%x:%x:%x:%x:%x:%x:%x:%x
%x:%x:%x:%x:%x:%x:%d.%d.%d.%d
/etc/hosts
/etc/services
/udp
/tcp
127.0.0.1
options
ndots:
attempts:
timeout:
nameserver
search
/bin/sh
/tmp/tmpnam_XXXXXX
-0X+0X 0X-0x+0x 0x
-+   0X0x
(null)
0123456789ABCDEF
M(knN
__vdso_clock_gettime
LINUX_2.6
%Y-%m-%d
+%lld
%+.2d%.2d
%0*lld
%&'()*+,
9:;<=>
BCDEFGHI
JKLMN
XYZ[
infinity
 !"#
 !"#
/proc/self/fd/
^[yY]
^[nN]
Sunday
Monday
Tuesday
Wednesday
Thursday
Friday
Saturday
January
February
March
April
June
July
August
September
October
November
December
%a %b %e %T %Y
%m/%d/%y
%H:%M:%S
%I:%M:%S %p
%m/%d/%y
0123456789
%a %b %e %T %Y
%H:%M:%S
C.UTF-8
LC_ALL
LANG
MUSL_LOCPATH
LC_CTYPE
LC_NUMERIC
LC_TIME
LC_COLLATE
LC_MONETARY
LC_MESSAGES
/etc/passwd
/var/run/nscd/socket
/etc/localtime
TZif
/usr/share/zoneinfo/
/share/zoneinfo/
/etc/zoneinfo/
zPLR
E.0{.
E.0{.
C.UTF-8
tqKj
lsM1w
- @YV
bar+_
QNT4
}^UiB=YKjA
9U1[IZ""!rLV
YD6%#axN
A\<~~P-F7X
yLU 
pZz&Y
Y`Z?
p<y@T 
=y1_
7S^HtF0X
2[=M[S
_xDDHe
>rnV'+%_2S(#
cp -f  %s /bin/wipefs>/dev/null 2>&1
ln -fs /bin/wipefs /etc/init.d/wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc0.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc1.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc2.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc3.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc4.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc5.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc6.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc0.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc1.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc2.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc3.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc4.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc5.d/S01wipefs>/dev/null 2>&1
ln -fs /etc/init.d/wipefs /etc/rc.d/rc6.d/S01wipefs>/dev/null 2>&1
touch -r /bin/sh /bin/wipefs /etc/init.d/wipefs /etc/rc.d/rc*.d/S01wipefs>/dev/null 2>&1
c|w{
9JLX
~=d]


"

// i couldn't write full $hex1  cuz every time i do it the terminal hangs !!  due to the BIG SIZE 


        $hex1 = { 

00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  02 00 3e 00 01 00 00 00  ff 15 40 00 00 00 00 00  |..>.......@.....|
00000020  40 00 00 00 00 00 00 00  b0 5c 24 00 00 00 00 00  |@........\$.....|
00000030  00 00 00 00 40 00 38 00  05 00 40 00 12 00 11 00  |....@.8...@.....|
00000040  01 00 00 00 05 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 40 00 00 00 00 00  00 00 40 00 00 00 00 00  |..@.......@.....|
00000060  3c df 23 00 00 00 00 00  3c df 23 00 00 00 00 00  |<.#.....<.#.....|
00000070  00 00 20 00 00 00 00 00  01 00 00 00 06 00 00 00  |.. .............|
00000080  80 e2 23 00 00 00 00 00  80 e2 83 00 00 00 00 00  |..#.............|
00000090  80 e2 83 00 00 00 00 00  88 79 00 00 00 00 00 00  |.........y......|
000000a0  08 bc 00 00 00 00 00 00  00 00 20 00 00 00 00 00  |.......... .....|
000000b0  07 00 00 00 04 00 00 00  80 e2 23 00 00 00 00 00  |..........#.....|
000000c0  80 e2 83 00 00 00 00 00  80 e2 83 00 00 00 00 00  |................|
000000d0  00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00  |................|
000000e0  08 00 00 00 00 00 00 00  51 e5 74 64 06 00 00 00  |........Q.td....|
000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000110  00 00 00 00 00 00 00 00  10 00 00 00 00 00 00 00  |................|
00000120  52 e5 74 64 04 00 00 00  80 e2 23 00 00 00 00 00  |R.td......#.....|
00000130  80 e2 83 00 00 00 00 00  80 e2 83 00 00 00 00 00  |................|
00000140  80 6d 00 00 00 00 00 00  80 6d 00 00 00 00 00 00  |.m.......m......|
00000150  01 00 00 00 00 00 00 00  50 e8 cb 15 00 00 e8 fd  |........P.......|
00000160  cd 0c 00 58 c3 00 00 00  00 00 00 00 00 00 00 00  |...X............|
00000170  41 54 55 53 31 db 83 bf  84 4e 00 00 0a c6 87 88  |ATUS1....N......|
00000180  4e 00 00 00 0f 84 86 00  00 00 48 89 f8 8b be 30  |N.........H....0|
00000190  02 00 00 83 ff 0a 74 78  48 8b 88 08 04 00 00 7f  |......txH.......|
000001a0  06 48 83 f9 01 74 69 48  85 c9 74 07 31 db 48 ff  |.H...tiH..t.1.H.|
000001b0  c9 7e 5d 31 db 83 ff 14  74 56 48 89 f7 48 8d 35  |.~]1....tVH..H.5|
000001c0  b3 d7 1f 00 49 89 d4 48  89 c5 e8 71 57 03 00 48  |....I..H...qW..H|
000001d0  85 c0 74 1e 48 8d 15 a4  d7 1f 00 48 8d 35 95 d7  |..t.H......H.5..|
000001e0  1f 00 48 89 c7 e8 a6 67  03 00 88 85 88 4e 00 00  |..H....g.....N..|
000001f0  eb 1e 48 8d 35 93 d7 1f  00 31 c0 4c 89 e7 e8 dd  |..H.5....1.L....|
00000200  64 03 00 85 c0 89 c3 75  07 c6 85 88 4e 00 00 01  |d......u....N...|
00000210  89 d8 5b 5d 41 5c c3 81  ff 00 20 00 00 0f 84 78  |..[]A\.... ....x|
00000220  01 00 00 0f 87 bd 00 00  00 83 ff 40 b8 40 00 00  |...........@.@..|
00000230  00 0f 84 8b 01 00 00 77  4a 83 ff 04 0f 84 4d 01  |.......wJ.....M.|
00000240  00 00 77 15 ff cf b8 01  00 00 00 83 ff 01 0f 86  |..w.............|
00000250  6e 01 00 00 e9 66 01 00  00 83 ff 10 b8 10 00 00  |n....f..........|
00000260  00 0f 84 5b 01 00 00 83  ff 20 b8 20 00 00 00 0f  |...[..... . ....|
00000270  84 4d 01 00 00 83 ff 08  0f 85 41 01 00 00 e9 0c  |.M........A.....|
00000280  01 00 00 81 ff 00 02 00  00 b8 00 02 00 00 0f 84  |................|
00000290  2e 01 00 00 77 1d 81 ff  80 00 00 00 0f 84 f3 00  |....w...........|
000002a0  00 00 81 ff 00 01 00 00  0f 84 e7 00 00 00 e9 0c  |................|
000002b0  01 00 00 81 ff 00 08 00  00 b8 00 08 00 00 0f 84  |................|
000002c0  fe 00 00 00 81 ff 00 10  00 00 0f 84 cb 00 00 00  |................|
000002d0  81 ff 00 04 00 00 b8 00  04 00 00 0f 84 e1 00 00  |................|
000002e0  00 e9 d9 00 00 00 81 ff  00 00 10 00 0f 84 c1 00  |................|
000002f0  00 00 77 4e 81 ff 00 00  01 00 0f 84 a7 00 00 00  |..wN............|
00000300  77 1d 81 ff 00 40 00 00  0f 84 93 00 00 00 81 ff  |w....@..........|
00000310  00 80 00 00 0f 84 87 00  00 00 e9 a0 00 00 00 81  |................|
00000320  ff 00 00 04 00 b8 00 00  04 00 0f 84 92 00 00 00  |................|
00000330  81 ff 00 00 08 00 74 75  81 ff 00 00 02 00 75 7f  |......tu......u.|
00000340  eb 65 81 ff 00 00 00 01  74 69 77 24 81 ff 00 00  |.e......tiw$....|
00000350  40 00 b8 00 00 40 00 74  69 81 ff 00 00 80 00 74  |@....@.ti......t|
00000360  4c 81 ff 00 00 20 00 b8  00 00 20 00 74 54 eb 4f  |L.... .... .tT.O|
00000370  81 ff 00 00 00 04 74 41  81 ff 00 00 00 08 74 39  |......tA......t9|
00000380  81 ff 00 00 00 02 b8 00  00 00 02 74 35 eb 30 b8  |...........t5.0.|
00000390  04 00 00 00 c3 b8 80 00  00 00 c3 b8 00 10 00 00  |................|
000003a0  c3 b8 00 40 00 00 c3 b8  00 00 01 00 c3 b8 00 00  |...@............|
 }

    condition:
        any of them
}

