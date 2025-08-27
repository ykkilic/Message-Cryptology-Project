// db_utils.h
#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <libpq-fe.h>

PGconn* connection(const char* conninfo);
void clear_obj(PGconn* conn, PGresult* res);
void exec_insert_query(PGconn* conn, const char* query);
PGresult* exec_query(PGconn* conn, const char* query);

#endif // DB_UTILS_H
