---
title: Password Cracking
parent: Categories
nav_order: 4
has_children: false
layout: default
---

# Password Cracking

## Context

I find Password Cracking (to be referred to as "Password" moving forward) to be a fascinating topic. There are entire competitions centered around the subject. Although I have never taken part in any of these password cracking-specific competitions, I do have experience with Password in certain competitions.

Most of my Password experience comes from National Cyber League, or NCL. NCL is a CTF competition organized into numerous categories (roughly seven, depending on the specific competition). One of these categories, as I am sure you can guess, is Password Cracking.

## Methodology

### Step 1: Get the Low-Hanging Fruit (Online Tools)

If the hash is relatively simple, online cracking tools are surprisingly effective. I usually try:

 * (CrackStation.net)[https://crackstation.net]
 * (Hashes.com)[https://hashes.com]
 * (Weakpass.com)[https://weakpass.com/tools/lookup]
 * (OnlineHashCrack.com)[https://www.onlinehashcrack.com/]
 * (MD5Decrypt.net)[https://md5decrypt.net/en/]


### Step 2: Hash Identification

If that doesn't get it, I know I'll have to do a bit more work. The first step is to figure out what type of hash you're dealing with.

There are a few options to do so:

**Option 1**: `hash-identifier`

`hash-identifier` is my go-to tool for hash identification. This is largely because it is default on Kali Linux--my favorite flavor of Linux.

To use `hash-identifier`, you can simply run:
```bash
$ hash-identifier <hash>
```

For more info, see:
 * https://www.kali.org/tools/hash-identifier/
 * https://github.com/blackploit/hash-identifier

**Option 2**: `hashid.py`

Another great option is `hashid.py`. This hash identifier not only identifies the hash, but also displays the corresponding Hashcat mode and/or JohnTheRipper format in its output.

To use `hashid.py`, you can simply run:
```bash
$ ./hashid.py '<hash>'
```

For more info, see:
 * https://github.com/psypanda/hashID

### Step 3: Wordlist

At this point, you know what type of hash you are working with is (or at least, you have it narrowed down to a few options) and you are ready for the next stage: the wordlist.

There are a few steps you should take at this point to either 1) formulate or 2) obtain the appropriate wordlist.

The first thing I like to do at this point is look at the **title** and **description** of the challenge. This may give you insight into what the wordlist might look like. For example, if the title of the challenge is "Full House", perhaps all of the passwords have something to do with the episode names or characters in the *Full House* television series.

Thus, the next thing I would do is see if there is an already-made wordlist for the topic. I might try searching for "full house episodes wordlist site:github", or other variations. Google Dorking can be very useful here.

If my searching came up short, the next thing I might do if I saw the challenge name was "Full House" is immediately go to the (List of Full House episodes Wikipedia page)[https://en.wikipedia.org/wiki/List_of_Full_House_episodes] (which I just found with a simple Google search), copy and paste each table with the list of episode names into Google Sheets (or Excel), delete all but the one column which holds the episode names, clean the episode names and make all variations of them, and get to cracking the password.

> Keep in mind, in some instances, you will not generate a wordlist at all. Instances of this might be if you are doing a mask attack (which I will discuss later).

### Step 4: Cracking the Hash(es)!

Cracking hashes is rather straightforward, but can vary widely in the specific command based on your circumstances.

There are two main tools you can use for password cracking: JohnTheRipper (aka. John) or Hashcat. I prefer John for simpler tasks, as well as certain advanced tasks. I prefer Hashcat for most advanced tasks. Knowing how to use both can significantly improve your efficiency during CTFs or professional assessments.

**JohnTheRipper**

JohnTheRipper, or JtR, is best for **simple, fast-crack scenarios** and **CPU-intensive environments**.

Basic usage:
```bash
# Crack using a dictionary
john --wordlist=rockyou.txt hashfile.txt

# See cracked passwords
john --show hashfile.txt

# If the hash type is ambiguous, use --format option explicitly
john --format=raw-md5 --wordlist=rockyou.txt hashfile.txt
```

**Hashcat**

Hashcat is best for **high-speed cracking using GPU acceleration**, **custom and complex attack modes**, and **handling large hashlists or complex hash types**.

**Syntax reminder:**
```bash
hashcat -m <hash_mode> -a <attack_mode> -o found.txt hashfile.txt [attack-specific-params]
```

Advanced usage:
```bash
# 1. Dictionary Attack (-a 0) -- applies a wordlist against the hash; this is the most common attack mode
hashcat -m 0 -a 0 -o found.txt hashes.txt rockyou.txt

# 2. Combinator Attack (-a 1) -- useful for cracking passwords like `admin123`, `summer2024` by combining two words
hashcat -m 0 -a 1 hashes.txt list1.txt list2.txt

# 3. Mask Attack (-a 3) -- tries passwords character-by-character using patterns, useful for brute-forcing short passwords
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l

# 4. Hybrid Attack (-a 6 and -a 7) -- tries `password01`, `summer22`, etc
hashcat -m 0 -a 6 hashes.txt rockyou.txt ?d?d
```

There are also other advanced tactis you can use:

1. Combining 3+ Words

```bash
$ combinator3 wordlist1.txt wordlist2.txt wordlist3.txt | hashcat -m 0 -a 0 hashes.txt --stdin
```

2. Rule-Based Mutations

```bash
$ hashcat -m 0 -a 0 -r rules/best64.rule hashes.txt rockyou.txt
```

## Other tips

Here are a few other useful tips I have picked up from my experience in password cracking (feel free to add your own tips as well!).

 * Use previously-cracked passwords to guide your decision making. For instance, if you've already cracked 3/5 passwords and they were all lowercase, you may want to focus your wordlist on lowercase options only
