#include <iostream>
#include <libpq-fe.h>
#include <algorithm>
#include <string>

using namespace std;

PGconn* connection(const char* conninfo) {
    PGconn* conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "Connection to database failed: " << PQerrorMessage(conn) << endl;
        PQfinish(conn);
        throw runtime_error("Bağlantı Başarısız");
    }
    // cout << "Başarıyla Bağlandı" << endl;
    return conn;
}

void clear_obj(PGconn* conn, PGresult* res){
    PQclear(res);
    PQfinish(conn);
}

void exec_insert_query(PGconn* conn, const char* query) {
    PGresult* res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        cerr << "INSERT failed: " << PQerrorMessage(conn) << endl;
        clear_obj(conn, res);
        throw runtime_error("Veri Eklenirken Bir hata oluştu");
    }
}

PGresult* exec_query(PGconn* conn, const char* query) {
    PGresult* res;
    string query_copy(query);
    transform(query_copy.begin(), query_copy.end(), query_copy.begin(), ::tolower);
    if (query_copy.find("select") != string::npos) {
        res = PQexec(conn, query);
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            cerr << "HATA: " << PQerrorMessage(conn) << endl;
            clear_obj(conn, res);
        }
    } else if (query_copy.find("insert") != string::npos) {
        exec_insert_query(conn, query);
        return nullptr;
    } else {
        throw runtime_error("Bu sorguyu çalıştıramayız");
    }
    return res;
}

// int main() {

//     string conninfo = "host=localhost port=5432 dbname=blockchain user=postgres password=Bjk1903";
//     PGconn* conn = connection(conninfo.c_str());

//     PGresult* res = exec_query(conn, "INSERT INTO test_table(name, surname, age) VALUES ('İsmail', 'Kılıç', 46);");

//     // cout << "PostgreSQL version: " << PQgetvalue(res, 0, 0) << endl;

//     clear_obj(conn, res);
// }