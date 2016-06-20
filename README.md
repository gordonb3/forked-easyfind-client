# forked-easyfind-client

#### Description
This project started as a fork to [Excito/easyfind-client](https://github.com/Excito/easyfind-client) that replaces an old collection of perl and python based scripts for communicating with a dynamic DNS service for Excito B2 and B3 miniservers. Shamefully the new easyfind-client was written as a human interface command line tool only, whereas the original scripts returned json for interaction with a web based front end. Current Excito development seems to move away from having a web frontend, concentrating on upgrading the old Debian Squeeze based Bubba OS to vanilla Jessie. As a result, my proposed changes have not (yet) been accepted upstream. Because these changes are important for my [Excito B2|3 ("Bubba") overlay for Gentoo](https://github.com/gordonb3/bubba-overlay) that brings the original web front end to gentoo-on-b3 users I have decided to mirror the original project and add the json interface.

Note: The DDNS service uses hardware defined unique keys for authentication. Do not bother building this if you do not own one of the supported devices mentioned above.
