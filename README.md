#SHA25 For Dummys
##A naive straight forward implementation of the SHA256 algorithm in C++
---

This is a simple implementation of SHA256. I basically followed [this](http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf) description word for word.
My idea was to have a mainly educational implementation. It should be easy to read this code with the description side by side.
If you want to use it like a library go to town.

For convinience i added a siple struct for comparison and storage of hashes and some fuctions for reading hashes from strings.
Since this is a tiny hobby project for me I won't describe usage here (maybe later). The main.cpp file shows basically all there is to know about the usage of this "library".
Just provide a pointer and size of the object (or just the pointer) -> templates ftw.