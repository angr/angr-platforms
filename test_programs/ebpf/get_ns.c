#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int main()
{
	bpf_ktime_get_ns();
	return 42;
}
