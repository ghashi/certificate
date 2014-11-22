#ifndef __CERT_TIME_H_
#define __CERT_TIME_H_

#define TIME_BUFFER_SIZE 15

int compare_dates(char d1[TIME_BUFFER_SIZE], char d2[TIME_BUFFER_SIZE]);
void now(char date[TIME_BUFFER_SIZE]);

#endif // __CERT_TIME_H_
