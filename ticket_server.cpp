#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <tuple>

using std::tuple;
using std::string;
using std::cerr;
using std::cout;

const uint16_t DEFAULT_PORT_NUMBER = 2022;
const uint32_t DEFAULT_TIMEOUT = 5;
const long int MAX_PORT_NUMBER = 65535;
const long int MIN_PORT_NUMBER = 0;
const long int MAX_TIMEOUT = 86400;
const long int MIN_TIMEOUT = 1;
const uint8_t NUMBER_BASE = 10;
const string USAGE_MESSAGE = "Usage: [-f file] [-p port] [-t timeout]\n";

void validate_range(long int value, long int min, long int max, string&& option) {
    if (value < min || value > max) {
        cerr << option << " is expected to be in the range: <" << min << "; " << max << ">\n";
        exit(EXIT_FAILURE);
    }
}

long int parse_numerical(char* p)
{
    char* tmp;
    long int res = strtol(p, &tmp, NUMBER_BASE);
    if (*tmp != '\0'){
        cerr << "Numerical value expected as option!\n";
        exit(EXIT_FAILURE);
    }
    return res;
}

tuple<string, uint16_t, uint32_t> parse_arguments(int argc, char* argv[]) 
{
    string file_name;
    bool file_overwritten = false;
    long int port_number = DEFAULT_PORT_NUMBER;
    long int timeout = DEFAULT_TIMEOUT;

    int opt;
    while ((opt = getopt(argc, argv, "f:p:t:")) != -1) 
    {
        switch (opt)
        {
            case 'f':
                file_overwritten = true;
                file_name = optarg;
                break;
            case 'p':
                port_number = parse_numerical(optarg);
                validate_range(port_number, MIN_PORT_NUMBER, MAX_PORT_NUMBER, "PORT NUMBER");
                break;
            case 't':
                timeout = parse_numerical(optarg);
                validate_range(timeout, MIN_TIMEOUT, MAX_TIMEOUT, "TIMEOUT");
                break;
            default:
                cerr << USAGE_MESSAGE;
                exit(EXIT_FAILURE);
        }
    }
    if (!file_overwritten) {
        cerr << "File name was not provided!\n";
        exit(EXIT_FAILURE);
    }
    return {file_name, (uint16_t) port_number, (uint32_t) timeout};
}

int main(int argc, char* argv[]) {
    
    const auto [file_name, port_number, timeout] = parse_arguments(argc, argv);
    cout << file_name << " " << port_number << " " << timeout << std::endl;
    while (true)
    {
        
    }

    return EXIT_SUCCESS;
}

