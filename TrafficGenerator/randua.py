#!/usr/bin/env python
# -*- coding: utf-8 -*-

# by Naglis Jonaits <njonaitis@gmail.com>
# Original work by InvisibleMan

#modified by nathan hoisington

from __future__ import print_function
import random
import time
from datetime import date

platforms = {
    "Macintosh": ["68K", "PPC"],
    "Windows": ["Win3.11", "WinNT3.51", "WinNT4.0", "Windows NT 5.0",
                "Windows NT 5.1", "Windows NT 5.2", "Windows NT 6.0",
                "Windows NT 6.1", "Windows NT 6.2", "Win95", "Win98",
                "Win 9x 4.90", "WindowsCE"],
    "X11": ["Linux i686", "Linux x86_64"]
}


def random_date(interval_from, interval_to):
    assert interval_to > interval_from
    delta = (interval_to - interval_from).total_seconds() * random.random()
    return date.fromtimestamp(time.mktime(interval_from.timetuple()) + delta)


#TODO: cleanup, PEP8
def generate(platformlist = list(platforms.keys()),
             browserlist = ["chrome", "firefox", "ie", "opera"],
             securitylist= ["N", "U", "I"],
             versionoverride = False,
             ):
    platform = random.choice(platformlist)
    os = random.choice(platforms[platform])
    browser = random.choice(browserlist)
    security = random.choice(securitylist)
    if browser == "chrome":
        webkit = str(random.randint(500, 599))
        if versionoverride:
            version = versionoverride
        else:
            version = str(random.randint(0, 32)) + ".0" + str(random.randint(0, 1500)) + "." + str(random.randint(0, 999))
        return "Mozilla/5.0 (" + os + "; " + security + ";) AppleWebKit/" + webkit + ".0 (KHTML, live Gecko) Chrome/" + version + " Safari/" + webkit
    elif browser == "firefox":
        date_from = date(2000, 1, 1)
        date_to = date.today()
        gecko_date = random_date(date_from, date_to)

        gecko = "{0:04d}{1:02d}{2:02d}".format(*gecko_date.timetuple()[:3])

        #TODO: Calculate the latest version.
        if versionoverride:
            firefox_version = versionoverride
        else:
            firefox_version = "{0:}.0".format(random.randint(1, 26))

        return "Mozilla/5.0 (" + os + "; rv:" + firefox_version + "; " + security + ";) Gecko/" + gecko + " Firefox/" + firefox_version
    elif browser == "ie":
        if versionoverride:
            version=versionoverride
        else:
            version = str(random.randint(1, 10)) + ".0"
        engine = str(random.randint(1, 5)) + ".0"
        option = random.choice([True, False])
        if option == True:
            token = random.choice([".NET CLR", "SV1", "Tablet PC", "Win64; IA64", "Win64; x64", "WOW64"]) + "; "
        else:
            token = ""
        return "Mozilla/5.0 (compatible; MSIE " + version + "; " + os + "; " + security + "; " + token + "Trident/" + engine + ")"
    else:
        # Presto version
        # Presto used to be the layout engine for Opera until version 15.
        # Now it uses Blink.
        #TODO: Make the versioning smarter - less random, more in touch with
        # real Opera's versions
        major, minor, build = 2, random.randint(1, 12), random.randint(1, 999)
        presto_version = "{0:}.{1:}.{2:}".format(major, minor, build)

        # Opera version
        # Windows and OS X are currently at version 18.
        # Linux is behind at version 12.
        lower, upper = 10, 18
        if platform == "X11":
            upper = 12
        major, minor = random.randint(lower, upper), random.randint(0, 99)
        if versionoverride:
            opera_version = versionoverride
        else:
            opera_version = "{0:}.{1:}".format(major, minor)

        # The 9.80 version in front is left on purpose by Opera's developers
        # due to some sites, which rely on browser sniffing and fail to parse
        # version numbers with two digits, in this case 10.
        return "Opera/9.80 (" + os + "; " + security + ") Presto/" + presto_version + " Version/" + opera_version


def main():
    print(generate())


if __name__ == "__main__":
    main()
