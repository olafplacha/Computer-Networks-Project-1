#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <tuple>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <unordered_set>

using std::tuple;
using std::pair;
using std::string;
using std::vector;
using std::unordered_set;
using std::cerr;
using std::cout;

using tickets_count_t = uint16_t;
using events_collection_t = vector<pair<string, tickets_count_t>>;

const uint16_t DEFAULT_PORT_NUMBER = 2022;
const uint32_t DEFAULT_TIMEOUT = 5;
const long int MAX_PORT_NUMBER = 65535;
const long int MIN_PORT_NUMBER = 0;
const long int MAX_TIMEOUT = 86400;
const long int MIN_TIMEOUT = 1;
const uint8_t NUMBER_BASE = 10;
const uint8_t TICKET_CODE_LENGTH = 7;
const uint8_t COOKIE_LENGTH = 48;
const string USAGE_MESSAGE = "Usage: [-f file] [-p port] [-t timeout]\n";

struct Ticket
{
    string code;
};

// This singleton class is responsible for generating unique tickets.
class TicketGenerator {
    public:
        static TicketGenerator& getInstance()
        {
            static TicketGenerator instance(TICKET_CODE_LENGTH);
            return instance;
        }

        Ticket generateUniqueTicket() {
            Ticket ticket;
            string code;
            do
            {
                code = generateRandomCode();
            } while (used_codes.find(code) != used_codes.end());
            
            // Mark the code as used.
            used_codes.insert(code);
            ticket.code = code;
            return ticket;
        }

        // Delete copy constructor and copy assignment.
        TicketGenerator(TicketGenerator const&) = delete;
        void operator=(TicketGenerator const&) = delete;

    private:
        size_t code_len;
        unordered_set<string> used_codes;

        TicketGenerator(const size_t& code_len_) : code_len(code_len_) {};
        
        char generateRandomSymbol() const {
            static const char symbols[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return symbols[rand() % (sizeof(symbols) - 1)];
        }

        string generateRandomCode() const {
            string code;
            for (size_t i = 0; i < code_len; i++)
            {
                code += generateRandomSymbol();
            }
            return code;
        }
};

void validate_range(const long int& value, const long int& min, const long int& max, const string&& option) 
{
    if (value < min || value > max) {
        cerr << option << " is expected to be in the range: <" << min << "; " << max << ">\n";
        exit(EXIT_FAILURE);
    }
}

long int parse_numerical(const char* p)
{
    char* tmp;
    long int res = strtol(p, &tmp, NUMBER_BASE);
    if (*tmp != '\0') {
        cerr << "Numerical value expected as option!\n";
        exit(EXIT_FAILURE);
    }
    return res;
}

tuple<string, uint16_t, uint32_t> parse_arguments(const int& argc, char* argv[]) 
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

events_collection_t parse_input_file(const string& file_name)
{
    std::ifstream infile(file_name);
    if (infile.fail()) {
        cerr << "File does not exist or you do not have sufficient permissions to read it!\n";
        exit(EXIT_FAILURE);
    }

    events_collection_t collection;
    string line;
    string description;
    tickets_count_t tickets_count;
    bool flag = true;

    while (std::getline(infile, line)) {
        if (flag) {
            description = line;
        }
        else {
            std::istringstream(line) >> tickets_count;
            collection.push_back({description, tickets_count});
        }
        flag = !flag;
    }
    return collection;
}

int main(int argc, char* argv[]) 
{
    const auto [file_name, port_number, timeout] = parse_arguments(argc, argv);
    events_collection_t events_collection = parse_input_file(file_name);

    while (true)
    {
        
    }

    return EXIT_SUCCESS;
}

