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
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>

#define EVENTS 2
#define RESERVATION 4
#define TICKETS 6
#define BAD_REQUEST 255

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
using description_length_t = uint8_t;
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

        time_t getExpirationTime() const {
            return expiration_time;
        }

        vector<Ticket> collectTickets() {
            if (!completed) {
                // Generate tickets lazily, as soon as they are collected.
                completed = true;
                generateTickets();
            }
            return tickets;
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

        string getCookie() const {
            return cookie;
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
        vector<Ticket> tickets;
        bool completed;

        void generateTickets() {
            TicketGenerator& generator = TicketGenerator::getInstance();
            for (size_t i = 0; i < ticket_count; i++)
            {
                Ticket t = generator.generateUniqueTicket();
                tickets.push_back(t);
            }
        }
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

        ticket_count_t getTicketCount() const {
            return ticket_count;
        }

        string getDescription() const {
            return description;
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

        // Returns valid ptr iff reservation has been successfully created.
        reservation_ptr tryToCreateReservation(const event_id_t& event_id, const ticket_count_t& ticket_count) {
            // Before validating the request, clean up invalid reservations.
            cleanUpInvalidAndCompletedReservations();
            // Check if event_id is valid.
            if (event_id >= events_vec.size()) {
                // There is no event with provided event_id.
                return nullptr;
            }
            // Check if provided number of tickets is positive and if it would fit into UDP datagram.
            if (ticket_count == 0 || !notTooManyTickets(ticket_count)) {
                return nullptr;
            }
            // Try to create a reservation.
            event_ptr event = events_vec.at(event_id);
            bool success = event->reduceTicketCount(ticket_count);
            if (!success) {
                // There were not enough tickets!
                return nullptr;
            }
            // Create reservation.
            reservation_ptr reservation = createReservation(event, ticket_count);
            return reservation;
        }

        // Returns non-empty vector with tickets iff tickets can be collected.
        vector<Ticket> tryToCollectTickets(const reservation_id_t id, const string& cookie) {
            // Before checking if the tickets can be collected, clean up invalid reservations.
            cleanUpInvalidAndCompletedReservations();
            // The provided id will be in the reservation_map iff:
            // - either it wasn't collected yet and is still valid
            // - or is was collected before.
            vector<Ticket> tickets;
            auto it = reservations_map.find(id);
            if (it == reservations_map.end()) {
                // The request is invalid.
                return tickets;
            }
            reservation_ptr reservation = it->second;
            if (!reservation->compareCookie(cookie)) {
                // The cookie is invalid.
                return tickets;
            }
            tickets = reservation->collectTickets();
            return tickets;
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

        reservation_ptr createReservation(const event_ptr& event, const ticket_count_t& n) {
            reservation_id_t id = counter++;
            time_t expiration_time = std::time(0) + timeout;
            string cookie = generateUniqueCookie();
            reservation_ptr reservation = std::make_shared<Reservation>(id, expiration_time, n, cookie, event);

            // Insert the pending reservation into the queue.
            pending_reservations_queue.push_back(reservation);
            // And into the map.
            reservations_map.insert({id, reservation});
            return reservation;
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
    
    // Validates if unknown options were provided.
    int counter = 1;

    int opt;
    while ((opt = getopt(argc, argv, "f:p:t:")) != -1) 
    {
        counter += 2;
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
    else if (argc != counter) {
        cerr << USAGE_MESSAGE;
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

int prepare_ipv4_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        cerr << "Error occured while creating a socket! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    if (bind(socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        cerr << "Error occured while binding a socket! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }
    return socket_fd;
}

// Reads a message and sets the client's address.
size_t get_client_message(const int& socket_fd, struct sockaddr_in* client_address, char* buffer) {
    socklen_t address_length = sizeof(*client_address);
    
    ssize_t bytes_read = recvfrom(socket_fd, buffer, MAX_UDP_CAPACITY, 0, 
        (struct sockaddr *) client_address, &address_length);

    if (bytes_read < 0) {
        cerr << "Error occured while receiving a message from a socket! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }
    return bytes_read;
}

bool put_event_into_buffer(const event_ptr& event, const event_id_t& id, char* buffer, size_t& bytes_in_buffer) {
    // Check if it fits into the buffer.
    ticket_count_t ticket_count = event->getTicketCount();
    string description = event->getDescription();

    size_t size = sizeof(event_id_t) + sizeof(ticket_count_t) + sizeof(description_length_t) + 
        sizeof(char) * description.length();
    
    if (bytes_in_buffer + size > MAX_UDP_CAPACITY) {
        // Not enough space!
        return false;
    }

    // Put event id into the buffer.
    event_id_t id_conv = htonl(id);
    std::memcpy(buffer + bytes_in_buffer, &id_conv, sizeof(event_id_t));
    bytes_in_buffer += sizeof(event_id_t);

    // Put ticket count into the buffer.
    ticket_count_t ticket_count_conv = htons(ticket_count);
    std::memcpy(buffer + bytes_in_buffer, &ticket_count_conv, sizeof(ticket_count_t));
    bytes_in_buffer += sizeof(ticket_count_t);

    // Put description length into the buffer.
    description_length_t description_length = description.length();
    std::memcpy(buffer + bytes_in_buffer, &description_length, sizeof(description_length_t));
    bytes_in_buffer += sizeof(description_length_t);

    // Put description into the buffer.
    for (size_t i = 0; i < description_length; i++)
    {
        char c = description.at(i);
        std::memcpy(buffer + bytes_in_buffer, &c, sizeof(char));
        bytes_in_buffer += sizeof(char);
    }
    return true;
}

void process_get_events(const int& socket_fd, const struct sockaddr_in* client_address, char* buffer, EventDatabase& db) {
    // Get vector of events.
    vector<event_ptr> events = db.getEvents();
    
    // Prepare message to be sent out.
    buffer[0] = EVENTS;
    size_t bytes_in_buffer = 1;

    event_id_t i = 0;
    for(auto& event : events) {
        bool success = put_event_into_buffer(event, i++, buffer, bytes_in_buffer);
        if (!success) {
            // No more events fit into the buffer.
            break;
        }
    }

    ssize_t res = sendto(socket_fd, buffer, bytes_in_buffer, 0, (struct sockaddr *) client_address, 
        sizeof(*client_address));
    
    if (res < 0) {
        cerr << "Error occured while sending events to the client! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }
}

void send_bad_request_response(const int& socket_fd, const struct sockaddr_in* client_address, char* buffer, uint32_t code) {
    buffer[0] = BAD_REQUEST;
    uint32_t code_conv = htonl(code);
    std::memcpy(buffer + 1, &code_conv, sizeof(uint32_t));

    ssize_t res = sendto(socket_fd, buffer, 1 + sizeof(uint32_t), 0, (struct sockaddr *) client_address, 
        sizeof(*client_address));

    if (res < 0) {
        cerr << "Error occured while sending BAD_REQUEST message to the client! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }
}

struct __attribute__((packed)) reservation_request {
    message_t message_id;
    event_id_t event_id;
    ticket_count_t ticket_count;
};

struct __attribute__((packed)) reservation_response {
    message_t message_id;
    reservation_id_t reservation_id;
    event_id_t event_id;
    ticket_count_t ticket_count;
    char cookie[COOKIE_LENGTH];
    time_t expiration_time;
};

void process_get_reservation(const int& socket_fd, const struct sockaddr_in* client_address, char* buffer, EventDatabase& db) {
    reservation_request* message = (reservation_request *) buffer;
    message->event_id = ntohl(message->event_id);
    message->ticket_count = ntohs(message->ticket_count);
    
    // Try to place a reservation.
    reservation_ptr reservation = db.tryToCreateReservation(message->event_id, message->ticket_count);

    if (reservation == nullptr) {
        // The reservation failed.
        send_bad_request_response(socket_fd, client_address, buffer, message->event_id);
        return;
    }
    reservation_response response;
    response.message_id = RESERVATION;
    response.reservation_id = htonl(reservation->getId());
    response.event_id = htonl(message->event_id);
    response.ticket_count = htons(message->ticket_count);
    response.expiration_time = htobe64(reservation->getExpirationTime());
    string cookie = reservation->getCookie();
    for (size_t i = 0; i < COOKIE_LENGTH; i++)
    {
        response.cookie[i] = cookie.at(i);
    }
    
    // Put the response in the buffer.
    std::memcpy(buffer, &response, sizeof(reservation_response));

    ssize_t res = sendto(socket_fd, buffer, sizeof(reservation_response), 0, (struct sockaddr *) client_address, 
        sizeof(*client_address));

    if (res < 0) {
        cerr << "Error occured while sending reservation message to the client! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }
}

struct __attribute__((packed)) tickets_request {
    message_t message_id;
    reservation_id_t reservation_id;
    char cookie[COOKIE_LENGTH];
};

struct __attribute__((packed)) tickets_response {
    message_t message_id;
    reservation_id_t reservation_id;
    ticket_count_t ticket_count;
};

void process_get_tickets(const int& socket_fd, const struct sockaddr_in* client_address, char* buffer, EventDatabase& db) {
    tickets_request* message = (tickets_request *) buffer;
    message->reservation_id = ntohl(message->reservation_id);

    string cookie = "";
    for (size_t i = 0; i < COOKIE_LENGTH; i++)
    {
        cookie += message->cookie[i];
    }
     
    vector<Ticket> tickets = db.tryToCollectTickets(message->reservation_id, cookie);
    if (tickets.size() == 0) {
        // The request could not be fulfilled.
        send_bad_request_response(socket_fd, client_address, buffer, message->reservation_id);
        return;
    }

    ticket_count_t ticket_count = tickets.size();
    tickets_response response;
    response.message_id = TICKETS;
    response.reservation_id = htonl(message->reservation_id);
    response.ticket_count = htons(ticket_count);

    // Copy tickets' codes to array.
    size_t ticket_arr_len = TICKET_CODE_LENGTH * ticket_count;
    char tickets_arr[ticket_arr_len];
    size_t i = 0;
    for (auto& t : tickets) {
        for (size_t j = 0; j < TICKET_CODE_LENGTH; j++)
        {
            tickets_arr[i++] = t.code.at(j);
        }
    }

    // Put the response in the buffer.
    std::memcpy(buffer, &response, sizeof(tickets_response));
    std::memcpy(buffer + sizeof(tickets_response), &tickets_arr, ticket_arr_len);

    ssize_t res = sendto(socket_fd, buffer, sizeof(tickets_response) + ticket_arr_len, 0, 
        (struct sockaddr *) client_address, sizeof(*client_address));

    if (res < 0) {
        cerr << "Error occured while sending tickets to the client! Errno: " << errno << '\n';
        exit(EXIT_FAILURE);
    }
}

// Returns true iff message_id is known and the length is correct.
bool proper_message_length(const message_t& message_id, const size_t& bytes_read) {
    switch (message_id)
    {
        case 1:
            // GET_EVENTS.
            return bytes_read == sizeof(message_t);
        case 3:
            // GET_RESERVATION.
            return bytes_read == sizeof(message_t) + sizeof(event_id_t) + sizeof(ticket_count_t);
        case 5:
            // GET_TICKETS.
            return bytes_read == sizeof(message_t) + sizeof(reservation_id_t) + COOKIE_LENGTH * sizeof(char);
        default:
            // Unknown.
            return false;
    }
}

void process_client_request(const int& socket_fd, const struct sockaddr_in* client_address, 
    char* buffer, const size_t& bytes_read, EventDatabase& db) {
    message_t message_id = buffer[0];

    // Check if message_id is known and if the number of sent bytes is correct.
    if (!proper_message_length(message_id, bytes_read)) {
        // Ignore the message.
        return;
    }

    switch (message_id)
    {
        case 1:
            process_get_events(socket_fd, client_address, buffer, db);
            break;
        case 3:
            process_get_reservation(socket_fd, client_address, buffer, db);
            break;
        case 5:
            process_get_tickets(socket_fd, client_address, buffer, db);
            break;
    }
}

int main(int argc, char* argv[]) 
{
    const auto [file_name, port_number, timeout] = parse_arguments(argc, argv);
    events_collection_t events_collection = parse_input_file(file_name);
    
    // Create EventDatabase instance, which provides all required functionalities.
    EventDatabase db(events_collection, timeout);

    // Prepare a socket for IPv4 UDP communication.
    int socket_fd = prepare_ipv4_socket(port_number);

    // Prepare a buffer which can fit any UDP packet's content.
    char buffer[MAX_UDP_CAPACITY];

    while (true)
    {
        struct sockaddr_in client_address;
        size_t bytes_read = get_client_message(socket_fd, &client_address, buffer);
        process_client_request(socket_fd, &client_address, buffer, bytes_read, db);
    }

    close(socket_fd);
    return EXIT_SUCCESS;
}

