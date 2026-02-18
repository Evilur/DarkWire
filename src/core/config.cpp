#include "config.h"

#include "cstring"

Config::Parameter::Parameter(const Type type) : _type(type) {
    if (_type == INTEGER) _data = new int();
    else if (type == FLOAT) _data = new float();
    else _data = nullptr;
}

Config::Parameter::Parameter(const int data) :
    _type(INTEGER), _data(new int(data)) { }

Config::Parameter::Parameter(const float data) :
    _type(FLOAT), _data(new float(data)) { }

Config::Parameter::Parameter(const char* const data) :
    _type(STRING), _data(new char[strlen(data) + 1]) {
    strcpy((char*)_data, data);
}

Config::Parameter::~Parameter() {
    if (_type == INTEGER) delete (int*)_data;
    else if (_type == FLOAT) delete (float*)_data;
    else delete[] (char*)_data;
}

Config::Parameter& Config::Parameter::operator=(const int data) {
    if (_type != INTEGER) throw
        std::runtime_error("Settings::Parameter: Set<int> invalid type");
    *(int*)_data = data;
    return *this;
}

Config::Parameter& Config::Parameter::operator=(const float data) {
    if (_type != FLOAT) throw
        std::runtime_error("Settings::Parameter: Set<float> invalid type");
    *(float*)_data = data;
    return *this;
}

Config::Parameter& Config::Parameter::operator=(const char* const data) {
    if (_type == STRING) {
        delete[] (char*)_data;
        _data = new char[strlen(data)+ 1];
        strcpy((char*)_data, data);
    } else if (_type == INTEGER)
        *(int*)_data = atoi(data);
    else if (_type == FLOAT)
        *(float*)_data = atof(data);
    return *this;
}

Config::Parameter::operator int() const {
    if (_type != INTEGER) throw
            std::runtime_error("Settings::Parameter: Get<int> invalid type");
    return *(int*)_data;
}

Config::Parameter::operator float() const {
    if (_type != FLOAT) throw
            std::runtime_error("Settings::Parameter: Get<float> invalid type");
    return *(float*)_data;
}

Config::Parameter::operator const char*() const {
    /* If the parameter is already a string */
    if (_type == STRING) return (const char*)_data;

    /* If the parameter is an integer or a float */
    static char result[24];
    if (_type == INTEGER) snprintf(result, sizeof(result), "%d", *(int*)_data);
    else snprintf(result, sizeof(result), "%f", *(float*)_data);
    return result;
}
