# MANUALS 

<pre>
this tools using for browser forensic and analysis your browser access.log you can file the ip, path and anything in source code.

for the example:
python3 finder.py access.log


                                                                   
                         _______                                   
          .--.   _..._   \  ___ `'.         __.....__              
     _.._ |__| .'     '.  ' |--.\  \    .-''         '.            
   .' .._|.--..   .-.   . | |    \  '  /     .-''"'-.  `. .-,.--.  
   | '    |  ||  '   '  | | |     |  '/     /________\   \|  .-. | 
 __| |__  |  ||  |   |  | | |     |  ||                  || |  | | 
|__   __| |  ||  |   |  | | |     ' .'\    .-------------'| |  | | 
   | |    |  ||  |   |  | | |___.' /'  \    '-.____...---.| |  '-  
   | |    |__||  |   |  |/_______.'/    `.             .' | |      
   | |        |  |   |  |\_______|/       `''-...... -'   | |      
   | |        |  |   |  |                                 |_|      
   |_|        '--'   '--'                                          



/home/.local/lib/python3.10/site-packages/matplotlib/projections/__init__.py:63: UserWarning: Unable to import Axes3D. This may be due to multiple versions of Matplotlib being installed (e.g. as a system package and as a pip package). As a result, the 3D projection is not available.
  warnings.warn("Unable to import Axes3D. This may be due to multiple versions of "
=== NGINX LOG ANALYSIS ===

Jumlah Total Request: 1861
Jumlah IP Unik: 1

=== STATUS CODE ===
+---------------+---------+--------------+
|   Status Code |   Count | Percentage   |
+===============+=========+==============+
|           404 |    1848 | 99.30%       |
+---------------+---------+--------------+
|           403 |      12 | 0.64%        |
+---------------+---------+--------------+
|           200 |       1 | 0.05%        |
+---------------+---------+--------------+

=== REQUEST METHODS ===
+----------+---------+--------------+
| Method   |   Count | Percentage   |
+==========+=========+==============+
| GET      |    1860 | 99.95%       |
+----------+---------+--------------+
| POST     |       1 | 0.05%        |
+----------+---------+--------------+

=== TOP 10 ACCESSED PATHS ===
+----------------+---------+--------------+
| Path           |   Count | Percentage   |
+================+=========+==============+
| /randomfile1   |       2 | 0.11%        |
+----------------+---------+--------------+
| /frand2        |       2 | 0.11%        |
+----------------+---------+--------------+
| /.bash_history |       2 | 0.11%        |
+----------------+---------+--------------+
| /.bashrc       |       2 | 0.11%        |
+----------------+---------+--------------+
| /.cache        |       2 | 0.11%        |
+----------------+---------+--------------+
| /.config       |       2 | 0.11%        |
+----------------+---------+--------------+
| /.cvs          |       2 | 0.11%        |
+----------------+---------+--------------+
| /.cvsignore    |       2 | 0.11%        |
+----------------+---------+--------------+
| /.forward      |       2 | 0.11%        |
+----------------+---------+--------------+
| /.git/HEAD     |       2 | 0.11%        |
+----------------+---------+--------------+

=== TOP 10 IP ADDRESSES ===
+--------------+---------+--------------+
| IP Address   |   Count | Percentage   |
+==============+=========+==============+
| 192.168.18.6 |    1861 | 100.00%      |
+--------------+---------+--------------+

=== TOP 10 ERROR PATHS ===
+----------------+---------------+---------+
| Path           |   Status Code |   Count |
+================+===============+=========+
| /randomfile1   |           404 |       2 |
+----------------+---------------+---------+
| /frand2        |           404 |       2 |
+----------------+---------------+---------+
| /.bash_history |           404 |       2 |
+----------------+---------------+---------+
| /.bashrc       |           404 |       2 |
+----------------+---------------+---------+
| /.cache        |           404 |       2 |
+----------------+---------------+---------+
| /.config       |           404 |       2 |
+----------------+---------------+---------+
| /.cvs          |           404 |       2 |
+----------------+---------------+---------+
| /.cvsignore    |           404 |       2 |
+----------------+---------------+---------+
| /.forward      |           404 |       2 |
+----------------+---------------+---------+
| /.git/HEAD     |           404 |       2 |
+----------------+---------------+---------+

=== TOP 10 USER AGENTS ===
+----------------------------------------------------+---------+
| User Agent                                         |   Count |
+====================================================+=========+
| Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) |    1860 |
+----------------------------------------------------+---------+
| curl/8.12.1                                        |       1 |
+----------------------------------------------------+---------+
Warning: Ignoring XDG_SESSION_TYPE=wayland on Gnome. Use QT_QPA_PLATFORM=wayland to run on Wayland anyway.

VIsualisasi disimpan sebagai: status_distribution.png dan hourly_traffic.png

# FITURES

- FIND STATUS CODE
- FIND REQUEST METHODS
- FIND TOP 10 ACCESSED PATHS
- FIND TOP 10 IP ADDRESSES
- FIND TOP 10 ERROR PATHS
- FIND TOP 10 USER AGENTS
- VISUALING THE TRAFFIC AND THE DATA status_distribution.png dan hourly_traffic.png

</pre>

# VISUALIZATION

![hourly traffic](/hourly_traffic.png)
![status distribtion](/status_distribution.png)
