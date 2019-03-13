#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>


unsigned int telnetFilter_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph+iph->ihl*4;

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)&& iph->saddr == in_aton("10.0.2.4")) {
        return NF_DROP;
    }

//    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(80)&&
//        iph->saddr == in_aton("128.230.18.198")
//        ) {
//        return NF_DROP;
//    }

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->saddr == in_aton("10.0.2.5")) {
        return NF_DROP;
    }
    return NF_ACCEPT;
}


unsigned int telnetFilter_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph+iph->ihl*4;

    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->daddr == in_aton("10.0.2.4")) {
        return NF_DROP;
    }

	//www.syr.edu
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(80)&& 
	iph->daddr == in_aton("128.230.18.198") ) {
        return NF_DROP;
    }

	//www.facebook.com
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(80)&&
        iph->daddr == in_aton("31.13.71.36")) {
        return NF_DROP;
    }

    return NF_ACCEPT;
}


static struct nf_hook_ops telnetFilterHook_in;
static struct nf_hook_ops telnetFilterHook_out;


int setUpFilter(void) {
    printk(KERN_INFO "Registering Telnet filter in.\n");
    telnetFilterHook_in.hook = telnetFilter_in; //(*@\label{firewall:line:telnetHookfn}@*)
    telnetFilterHook_in.hooknum = NF_INET_PRE_ROUTING;
    telnetFilterHook_in.pf = PF_INET;
    telnetFilterHook_in.priority = NF_IP_PRI_FIRST;

    // Register the hook.
    nf_register_hook(&telnetFilterHook_in);
    printk(KERN_INFO "Registering a Telnet filter out.\n");
    telnetFilterHook_out.hook = telnetFilter_out; //(*@\label{firewall:line:telnetHookfn}@*)
    telnetFilterHook_out.hooknum = NF_INET_POST_ROUTING;
    telnetFilterHook_out.pf = PF_INET;
    telnetFilterHook_out.priority = NF_IP_PRI_FIRST;

    // Register the hook.
    nf_register_hook(&telnetFilterHook_out);
    return 0;
}



void removeFilter(void) {
    printk(KERN_INFO "Telnet filter is being removed.\n");
    nf_unregister_hook(&telnetFilterHook_in);
    nf_unregister_hook(&telnetFilterHook_out);

}



module_init(setUpFilter);
module_exit(removeFilter);



MODULE_LICENSE("GPL");


