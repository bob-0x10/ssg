Station Signal Generator
===

## How to use ssg in process level

```
ssg wlan0 "ether host 00:11:22:33:44:55"
```

## How to use ssg in code level

* Add all h and cpp file(except ssg.cpp) in src folder into your project.

* Add the following code in your project.
```cpp
Ssg ssg;
ssg.interface_ = "wlan0";
ssg.filter_ = "ether host " + apmac;
ssg.open();
```

* To stop sending beacon frames, call close function.
```cpp
ssg.close();
```


## Notice
* Before using ssg, wireless apdater must be monitor mode and set it's channel into AP channel.