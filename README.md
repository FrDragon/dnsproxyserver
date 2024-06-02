DNS proxy server 

#How to build the program?
You should start Makefile placed in this directory. As a result of Makefiles work you will get the dns proxy server thats ready for using. If you want to delete the result of Makefiles work, use the 'make clean' command in your directory.

#How to configure the server?
In the directory you have a file 'settings.conf'. On the first line you must specify an address of upstream dns server, on the second line - list of banned domains. Use the ',' or blankspace delimiters for splitting domain names in this line. On the third line you must specify a return code or pre-configured ip address that dns server will return in the case of banned domain matching. 

#How to run dns server?
Just enter the './dnsproxyserver' in your terminal. 
