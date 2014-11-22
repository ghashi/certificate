#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cert_time.h"

void strtotm(char datetime[TIME_BUFFER_SIZE], struct tm *timeinfo);
void tmtostr(struct tm *timeinfo, char datetime[TIME_BUFFER_SIZE]);

/**
 * compares dates d1 and d2
 * returns -1 if d1 >  d2;
 *          0 if d1 == d2
 *          1 if d1 <  d2
 * d1 and d2 should have the following format: YYYYMMDDhhmmss
 */
int compare_dates(char d1[TIME_BUFFER_SIZE], char d2[TIME_BUFFER_SIZE]){
  time_t raw_d1;
  time_t raw_d2;
  struct tm timeinfo_d1;
  struct tm timeinfo_d2;
  double difference;

  strtotm(d1, &timeinfo_d1);
  strtotm(d2, &timeinfo_d2);

  raw_d1 = mktime(&timeinfo_d1);
  raw_d2 = mktime(&timeinfo_d2);

  difference = difftime(raw_d1, raw_d2);
  if(difference > 0){
    return -1;
  } else if (difference < 0){
    return 1;
  } else {
    return 0;
  }
}

/**
 * get current time (format: YYYYMMDDhhmmss)
 *
 * date: declared char[TIME_BUFFER_SIZE]
 */
void now(char date[TIME_BUFFER_SIZE]){
  time_t rawtime;
  struct tm *timeinfo;

  time (&rawtime);
  timeinfo = gmtime(&rawtime);
  tmtostr(timeinfo, date);
}

/**
 * convert strcut tm to string YYYYMMDDhhmmss
 *
 * tm: ptr to struct tm with datetime data
 * datetime: declared char[TIME_BUFFER_SIZE]
 */
void tmtostr(struct tm *timeinfo, char datetime[TIME_BUFFER_SIZE]){
  strftime (datetime, TIME_BUFFER_SIZE, "%G%m%d%H%M%S", timeinfo);
}

/**
 * convert string YYYYMMDDhhmmss to strcut tm
 *
 * ex of datetime:     20141121181400
 * format:             YYYYMMDDhhmmss
 * index:              01234567890123
 *
 * datetime: char[TIME_BUFFER_SIZE] with YYYYMMDDhhmmss
 * tm: allocated ptr to struct tm
 */
void strtotm(char datetime[TIME_BUFFER_SIZE], struct tm *timeinfo){
  int i;
  char num[5];
  time_t rawtime;

  time(&rawtime);
  memcpy(timeinfo, localtime(&rawtime), sizeof(struct tm));

  // year
  for(i = 0; i < 4; i++)
    num[i] = datetime[i];
  num[4] = 0;
  timeinfo->tm_year  = atoi(num) - 1900;

  // month
  num[0] = datetime[4];
  num[1] = datetime[5];
  num[2] = 0;
  num[3] = 0;
  timeinfo->tm_mon   =  atoi(num) - 1;

  // day
  num[0] = datetime[6];
  num[1] = datetime[7];
  timeinfo->tm_mday  = atoi(num);

  // hour
  num[0] = datetime[8];
  num[1] = datetime[9];
  timeinfo->tm_hour	 = atoi(num);

  // min
  num[0] = datetime[10];
  num[1] = datetime[11];
  timeinfo->tm_min	 = atoi(num);

  // sec
  num[0] = datetime[12];
  num[1] = datetime[13];
  timeinfo->tm_sec	 = atoi(num);
}
