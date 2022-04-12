#include <unistd.h>
#include <iostream>
#include <stdlib.h>
#include <tuple>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <deque>
#include <chrono>

using std::tuple;
using std::pair;
using std::string;
using std::vector;
using std::unordered_set;
using std::unordered_map;
using std::deque;
using std::cerr;
using std::cout;

using message_t = uint8_t;
using timeout_t = uint32_t;
using ticket_count_t = uint16_t;
using event_id_t = uint32_t;
using reservation_id_t = uint32_t;
using events_collection_t = vector<pair<string, ticket_count_t>>;

class Reservation;
using reservation_ptr = std::shared_ptr<Reservation>;

class Event;
using event_ptr = std::shared_ptr<Event>;

const uint16_t DEFAULT_PORT_NUMBER = 2022;
const timeout_t DEFAULT_TIMEOUT = 5;
const long int MAX_PORT_NUMBER = 65535;
const long int MIN_PORT_NUMBER = 0;
const long int MAX_TIMEOUT = 86400;
const long int MIN_TIMEOUT = 1;
const uint8_t NUMBER_BASE = 10;
const uint8_t TICKET_CODE_LENGTH = 7;
const size_t COOKIE_LENGTH = 48;
const uint8_t MIN_COOKIE_CODE = 33;
const uint8_t MAX_COOKIE_CODE = 126;
const size_t MAX_UDP_CAPACITY = 65507;
const reservation_id_t MIN_RESERVATION_ID = 1000000;
const string USAGE_MESSAGE = "Usage: [-f file] [-p port] [-t timeout]\n";

class Reservation {
    public:
        Reservation(const reservation_id_t& id_, const time_t& expiration_time_, const ticket_count_t& ticket_count_, 
            const string& cookie_, const event_ptr& event_): id(id_), expiration_time(expiration_time_), 
            ticket_count(ticket_count_), cookie(cookie_), event(event_), completed(false) {};

        reservation_id_t getId() const {
            return id;
        }

        event_ptr getEvent() const {
            return event;
        }

        void complete() {
            completed = true;
        }

        bool isCompleted() const {
            return completed;
        }

        bool isValid() const {
            return expiration_time >= std::time(0);
        }

        ticket_count_t getNumberOfTicketsReserved() const {
            return ticket_count;
        }

        bool compareCookie(const string& cookie_) const {
            return cookie == cookie_;
        }

    private:
        const reservation_id_t id;
        const time_t expiration_time;
        const ticket_count_t ticket_count;
        const string cookie;
        const event_ptr event;
        bool completed;
};

// This class represents one event.
class Event {
    public:
        Event(const string& description_, const ticket_count_t ticket_count_) : description(description_),
            ticket_count(ticket_count_) {};

        bool reduceTicketCount(ticket_count_t num) {
            if (num > ticket_count) {
                // There are not enough tickets!
                return false;
            }
            ticket_count -= num;
            return true;
        }

        void increaseTicketCount(ticket_count_t num) {
            ticket_count += num;
        }

    private:
        const string description;
        ticket_count_t ticket_count;
        
};

// This class takes care of all operations performed on events.
class EventDatabase {
    public:
        EventDatabase(const events_collection_t& events_collection, const timeout_t& timeout_) 
            : counter(MIN_RESERVATION_ID), timeout(timeout_) {
            // Create Event instances.
            for (auto& p : events_collection) {
                event_ptr event = std::make_shared<Event>(p.first, p.second);
                events_vec.push_back(event);
            }
        }

        vector<event_ptr> getEvents() {
            // Before events are returned, invalid reservations have to be cleaned up.
            cleanUpInvalidAndCompletedReservations();
            return events_vec;
        }

        // Returns true iff reservation has been successfully created.
        pair<bool, reservation_id_t> tryToCreateReservation(event_id_t event_id, ticket_count_t ticket_count) {
            // Before validating the request, clean up invalid reservations.
            cleanUpInvalidAndCompletedReservations();
            // Check if event_id is valid.
            if (event_id >= events_vec.size()) {
                // There is no event with provided event_id.
                return {false, 0};
            }
            // Check if provided number of tickets is positive and if it would fit into UDP datagram.
            if (ticket_count == 0 || !notTooManyTickets(ticket_count)) {
                return {false, 0};
            }
            // Try to create a reservation.
            event_ptr event = events_vec.at(event_id);
            bool success = event->reduceTicketCount(ticket_count);
            if (!success) {
                // There were not enough tickets!
                return {false, 0};
            }
            // Create reservation.
            reservation_id_t id = createReservation(event, ticket_count);
            return {true, id};
        }

        // Copied EventDatabase could lead to fatal bugs, e.g. tickets being gave back twice.
        // Therefore copy constructor and copy assignment operator are deleted.
        EventDatabase(EventDatabase const&) = delete;
        void operator=(EventDatabase const&) = delete;

    private:
        reservation_id_t counter;
        const timeout_t timeout;
        vector<event_ptr> events_vec;
        deque<reservation_ptr> pending_reservations_queue;
        unordered_map<reservation_id_t, reservation_ptr> reservations_map;

        static bool notTooManyTickets(ticket_count_t n) {
            size_t ticket_size = sizeof(char) * TICKET_CODE_LENGTH;
            size_t req = sizeof(message_t) + sizeof(reservation_id_t) + sizeof(ticket_count_t) + n * ticket_size;
            return req <= MAX_UDP_CAPACITY;
        }

        reservation_id_t createReservation(const event_ptr& event, const ticket_count_t n) {
            reservation_id_t id = counter++;
            time_t expiration_time = std::time(0) + timeout;
            string cookie = generateUniqueCookie();
            reservation_ptr reservation = std::make_shared<Reservation>(id, expiration_time, n, cookie, event);

            // Insert the pending reservation into the queue.
            pending_reservations_queue.push_back(reservation);
            // And into the map.
            reservations_map.insert({id, reservation});
            return id;
        }

        static string generateRandomCookie() {
            string cookie;
            for (size_t i = 0; i < COOKIE_LENGTH; i++)
            {
                char c = MIN_COOKIE_CODE + rand() % (MAX_COOKIE_CODE - MIN_COOKIE_CODE + 1);
                cookie += c;
            }
            return cookie;
        }

        string generateUniqueCookie() const {
            static unordered_set<string> taken_cookies;
            string cookie;
            do
            {
                cookie = generateRandomCookie();
            } while (taken_cookies.find(cookie) != taken_cookies.end());
            taken_cookies.insert(cookie);
            return cookie;
        }

        // This method removes reservations which are invalid or have been completed (corresponding tickets
        // have been collected by the client) from the beginning of the deque.
        //
        // As soon as this method returns, the following invariant will hold:
        // - either the pending_reservations deque will be empty
        // - or the first element of the deque will be a valid reservation.
        // 
        // Reservations, which are added to the pending_reservations deque, have increasing expiration date.
        // It implies, that after the method returns, each reservation in the deque will be:
        // - either still valid
        // - or yet completed.
        void cleanUpInvalidAndCompletedReservations() {
            while (pending_reservations_queue.size() > 0) {
                reservation_ptr r = pending_reservations_queue.front();
                if (r->isCompleted()) {
                    // The reservation is completed, tickets were already collected by the client.
                    pending_reservations_queue.pop_front();
                }
                else if (!r->isValid()) {
                    // The reservation is not valid.
                    pending_reservations_queue.pop_front();
                    
                    // Give back the reserved tickets.
                    ticket_count_t r_ticket_count = r->getNumberOfTicketsReserved();
                    event_ptr r_event = r->getEvent();
                    r_event->increaseTicketCount(r_ticket_count);

                    // Delete the reservation from the reservation map.
                    reservation_id_t r_id = r->getId();
                    reservations_map.erase(r_id);
                }
                else {
                    // The reservation is not completed and still valid. Reservations after this point
                    // must be either valid or completed.
                    break;
                }
            }
        }
};

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
    ticket_count_t tickets_count;
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

