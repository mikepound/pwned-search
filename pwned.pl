#!/usr/bin/perl

# This is a perl version of the original pwned-search created by Dr. Mike Pound
# This program is a free software. You are free to use it under the terms of
# GNU GPL license either version 3 or, at your choice, any later version.
# Copyright 2019 Lucas V. Araujo <lucas.vieira.ar@disroot.org>
# Required module: WWW::Curl::Easy (libwww-curl-perl)

use strict;
use warnings;
use Getopt::Long;
use WWW::Curl::Easy;
use Digest::SHA qw(sha1_hex);

use vars qw ( $VERSION );

$VERSION = "2019.1208.0012";

sub request
{
    # Performs an http request to a given url using the WWW::Curl::Easy module
    # and returns, if successful, the received page.

    #gets the url passed as argument
    my $url  = shift;
    my $prxy = shift;
    #initialize a new instance of Curl::Easy
    my $curl = WWW::Curl::Easy->new();
    #define the HEADER option as true
    $curl->setopt(CURLOPT_HEADER, 1);
    #define the target url
    $curl->setopt(CURLOPT_URL, $url);
    #declare a variable to hold the returned page
    my $data = undef;
    #define the variable as a filehandle to store the data into
    $curl->setopt(CURLOPT_WRITEDATA, \$data);
    #sets the proxy to be used, if any
    $curl->setopt(CURLOPT_PROXY, $prxy) if $prxy;
    #performs the request
    my $err = $curl->perform();

    #checks if successfull
    unless ($err)
    {
        return $data;
    }
    else
    {
        print("error: $err ".$curl->strerror($err)."\n".$curl->errbuf."\n");
        return "";
    }
}


sub lookup_password
{
    #Given a plain password, gets the hash and search for it on the database
    #using the especified proxy

    my $plain  = shift;
    my $proxy  = shift;
    #get the SHA-1 hashed password
    my $hashed = sha1_hex($plain);
    #separate the hash into a head containing the first 5 bytes, and a tail
    #containing the rest
    $hashed    =~ /([\d\w]{5})([\d\w]*)/;
    my $head   = $1;
    my $tail   = $2;
    #format the head into a url to be requested
    my $url    = "https:\/\/api.pwnedpasswords.com\/range\/$head";
    #realize the request and get the response
    my $resp   = request($url, $proxy);
    #if nothing is found, it is considered that the number of times it leaked
    #(for all we know) was 0
    my $count = 0;
    #match the response against a regular expression to extract the number of
    #times that the password was been leaked
    if ($resp =~ /$tail\:([\d]*)/i )
    {
        $count = $1;
    }
    #returns an array with the hash and the count
    return ($hashed, $count);
}

sub main
{
    my $version  = 0;
    my $proxy    = undef;
    my $help     = 0;
    my $tor      = 0;
    

    GetOptions(
        "version!" => \$version,
        "proxy=s"  => \$proxy,
        "help!"    => \$help,
        "tor!"     => \$tor,
    );

    if ($version)
    {
        print "$VERSION\n";
        exit(0);
    }

    if ($help || !(scalar @ARGV))
    {
        print "pwned-search  -  Pwned Password API lookup tool\n\n" .
        "usage: pwned.pl [options] <password0> ... <passwordN>\n\n" .
        "Options:\n" .
        "-v, --version  show program's version number and exit\n" .
        "-h, --help     show this help message and exit\n" .
        "-p, --proxy    define a proxy to be used in requests\n" .
        "               (the proxy must be in format TYPE://ADDRESS[:PORT])\n" .
        "-t, --tor      use tor proxy\n" .
        "               (same as --proxy=socks5://127.0.0.1:9050)\n\n" .
        "This is a perl version of the pwned-search by Dr. Mike Pound\n" .
        "Copyright (C) 2019 Lucas V. Araujo <lucas.vieira.ar\@disroot.org>\n" .
        "GitHub: https://github.com/LvMalware/pwned-search \n";
        exit(0);
    }

    $proxy = "socks5://127.0.0.1:9050" if $tor;
    
    for my $password (@ARGV)
    {
        my ($hash, $count) = lookup_password($password, $proxy);
        if ($count > 0)
        {
            print "$password was found with $count occurrences (hash: $hash)\n";
        }
        else
        {
            print "$password was not found\n";
        }
    }
}

main();
