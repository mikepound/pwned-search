#!/usr/bin/perl

# This is the perl version of pwned-search by Dr. Mike Pound
# Copyright 2019 Lucas V. Araujo <lucas.vieira.ar@disroot.org>
# Required module: WWW::Curl::Easy (libwww-curl-perl)

use strict;
use warnings;
use WWW::Curl::Easy;
use Digest::SHA qw(sha1_hex);

sub request
{
    # Performs an http request to a given url using the WWW::Curl::Easy module
    # and returns, if successful, the received page.

    #gets the url passed as argument
    my $url  = shift;
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
    #performs the request
    my $err = $curl->perform();

    #checks if successfull
    unless ($err)
    {
        return $data;
    }
    else
    {
        print("error: $err ".$curl->strerror($err)." ".$curl->errbuf."\n");
        return "";
    }
}


sub lookup_password
{
    #Given a plain password, gets the hash and search for it on the database
    
    my $plain  = shift;
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
    my $resp   = request($url);
    #if nothing is found, it is considered that the number of times it leaked
    #(for all we know) was 0
    my $count = 0;
    #match the response against a regular expression to extract the number of
    #times that the password was been leaked
    if ($resp  =~ /$tail\:([\d]*)/i )
    {
        $count = $1;
    }
    #returns an array with the hash and the count
    return ($hashed, $count);
}

sub main
{
    for my $password (@ARGV)
    {
        my ($hash, $count) = lookup_password($password);
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
