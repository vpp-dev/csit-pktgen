typedef struct {
	int num_ports;
	int num_tx_queues;
	int num_rx_queues;
	int packet_size;
} config_t;

config_t *get_config(void); /* configuration struct */
int parse_cmdline(int argc, char **argv);
