/*
 * Copyright 2021-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.foo.app;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;

import org.jboss.netty.handler.codec.socks.SocksMessage;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.*;
import org.onosproject.net.statistic.StatisticService;
import org.onosproject.net.topology.PathService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.onlab.packet.IpAddress.*;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent {

    ConcurrentHashMap<MacAddress, ConcurrentHashMap<DeviceId,PortNumber>> serverLookupTable = new ConcurrentHashMap<>();
    List<MacAddress> serverMacList = new ArrayList<>();

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;


    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;
    private String server1_mac = "00:00:00:00:00:05";
    private String server2_mac = "00:00:00:00:00:06";
    private String server3_mac = "00:00:00:00:00:07";
    private String LB_ID = "of:0000000000000001";

    private List<Integer> weight = new ArrayList<>();
    private List<Integer> currentWeight = new ArrayList<>();

    private int srcPort, dstPort = 0;
    private IpAddress serverIp = null;

    private Host targetServer = null;
    private MacAddress serverMac = null;
    private PortNumber outPort = null;
    private DeviceId dstDevice = null;

    private int requestsServed = 0;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.foo.app");
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        packetService.addProcessor(processor, PacketProcessor.director(2));
        log.info("Started", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            //Discard if  packet is null.
            if (ethPkt == null) {
                return;
            }

            /*First step is to handle the ARP requests.
            For that catch all ARP packets and construct and send back the ARP replies.
            */
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                log.info("ARP request received");
                ARP arpPacket = (ARP) ethPkt.getPayload();
                //Create an ARP reply packet with the LB's MAC:IP
                Ethernet arpReply;
                if ((!ethPkt.getSourceMAC().equals(MacAddress.valueOf(server1_mac))) |(!ethPkt.getSourceMAC().equals(MacAddress.valueOf(server2_mac))) | (!ethPkt.getSourceMAC().equals(MacAddress.valueOf(server3_mac)))) {
                    arpReply = arpPacket.buildArpReply(Ip4Address.valueOf("10.0.0.100"), MacAddress.valueOf("00:00:00:00:00:14"), ethPkt);
                    log.info("ARP reply to {}", ethPkt.getSourceMAC().toString());
                } else {
                    log.info("Other arp replies");
                    return;
                }
                //Send the ARP reply back to the host.
                log.info("ARP reply to {}", ethPkt.getSourceMAC().toString());
                for (Host host : hostService.getHostsByMac(ethPkt.getSourceMAC())) {
                    TrafficTreatment trafficTreatment = DefaultTrafficTreatment.builder().setOutput(host.location().port()).build();
                    ByteBuffer byteBuffer = ByteBuffer.wrap(arpReply.serialize());
                    OutboundPacket outboundPacket = new DefaultOutboundPacket(host.location().deviceId(), trafficTreatment, byteBuffer);
                    packetService.emit(outboundPacket);
                }
                return;
            }

            // From here on we handle only IPv4 packets.
            if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) return;
            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
            int srcPort_temp = 0;

            //If ICMP packet, return
            if(String.valueOf(ipv4Packet.getProtocol()).equals("1")) {
                log.info("IPV4 packet protocol is: " + String.valueOf(ipv4Packet.getProtocol()) + " => ICMP packet return!");
                return;
            }


            /*
             * clean & Add server IP list
             */
            serverMacList.removeAll(serverMacList);
            serverMacList.add(MacAddress.valueOf(server1_mac));
            serverMacList.add(MacAddress.valueOf(server2_mac));
            serverMacList.add(MacAddress.valueOf(server3_mac));
            log.info("Server mac list: " + String.valueOf(serverMacList));
            int size = serverMacList.size();



            //Create the Traffic Selector and start adding criteria.
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType(Ethernet.TYPE_IPV4);
            log.info("Initial Server Mac:" + serverMac);
            log.info("Initial src port" + srcPort);
            log.info("Initial dst port" + dstPort);


            //Handle TCP packets here.
            if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                TCP tcpPkt = (TCP) ipv4Packet.getPayload();
                srcPort_temp = tcpPkt.getSourcePort();
                log.info("TCP src port: " + srcPort);
                dstPort = tcpPkt.getDestinationPort();
                log.info("TCP dst port: " + dstPort);
                if (!(srcPort == srcPort_temp)) {
                    if (srcPort == dstPort) {
                        return;
                    } else {
                        srcPort = srcPort_temp;
                        log.info("TCP src port changes to: " + srcPort);
                    }
                } else {
                    if (!(serverIp == null)) {
                        if (hostService.getHostsByIp(serverIp).isEmpty()) {
                            log.warn("Cannot find server ip: " + String.valueOf(serverIp) + " Need a flow entry update");
                        }
                    } else {
                        return;
                    }
                }

                //Delete the previous device lookup table before update new ones
                serverLookupTable.clear();

                //Very important here: Specify the protocol (TCP, UDP) before specifying transport port.
                //Specifying only the transport port WILL NOT work.
                selector.matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(srcPort))
                        .matchTcpDst(TpPort.tpPort(dstPort));
            }
            //Handle UPD packets here.
            else if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
                UDP udpPkt = (UDP) ipv4Packet.getPayload();
                srcPort = udpPkt.getSourcePort();
                dstPort = udpPkt.getDestinationPort();
                selector.matchIPProtocol(IPv4.PROTOCOL_UDP).matchUdpSrc(TpPort.tpPort(srcPort))
                        .matchUdpDst(TpPort.tpPort(dstPort));
            }

            /*Initial information of the new session IP packet*/
            int deviceNums = topologyService.currentTopology().deviceCount();
            log.info("There are devices: " + deviceNums);

            IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());
            log.info("Src Ip: " + String.valueOf(srcIp));
            MacAddress srcMac = ethPkt.getSourceMAC();
            log.info("Src Mac: " + String.valueOf(srcMac));

            DeviceId lbDevice = deviceService.getDevice(DeviceId.deviceId(LB_ID)).id();
            DeviceId srcDevice = pkt.receivedFrom().deviceId();
            log.info("Src device: " + String.valueOf(srcDevice));
            PortNumber srcPortInit = pkt.receivedFrom().port();
            log.info("Src port: " + String.valueOf(srcPortInit));


            /*
             * Initial Selector
             */
            selector.matchIPDst(IpPrefix.valueOf(valueOf("10.0.0.100"), IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPSrc(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH));

            serverLookupTable = LookupTableUpdate(size);
            log.info("Lookup table update: "+ String.valueOf(serverLookupTable));

            /*
             * Select a server
             */
//            serverMac = outPortSelectionNoLB(); //Uncomment this when no LB
            serverMac = outPortSelectionRR(serverMacList);// For RR
            ConcurrentHashMap<DeviceId, PortNumber> devicePort = serverLookupTable.get(serverMac);
            ConcurrentHashMap.KeySetView<DeviceId, PortNumber> deviceset = devicePort.keySet();
            for (DeviceId td:deviceset){
                dstDevice = td;
                outPort = devicePort.get(td);
            }
            log.info("Chosen dst device: " + dstDevice + " Out port: " + outPort);
            Set<Host> hosts = hostService.getConnectedHosts(dstDevice);
            for (Host h:hosts){
                if(h.location().port().equals(outPort)){
                    targetServer = h;
                    serverIp = targetServer.ipAddresses().iterator().next();
                }
            }

            /*
             * Choose paths & install flow rules
             */
            int flag = 0;
            Path path = findBestPath(srcDevice, lbDevice);
            DeviceId linkDevice = null;
            List<Link> links;
            int len_link;
            if(path == null){
                forwardRequestEndEdge(srcIp, serverIp, serverMac, srcDevice, outPort);
                flag = 1;
                log.info("Request will be forwarded to H" + String.valueOf(targetServer));
            } else {
                links = path.links();
                len_link = links.size();
                for (int l = 0; l < len_link; l++) {
                    Link link = links.get(l);
                    if (l == len_link - 1) {
                        linkDevice = link.dst().deviceId();
                    } else {
                        linkDevice = link.src().deviceId();
                    }
                    forwardRequestPath(link, selector.build());
                    log.warn("link to LB no." + String.valueOf(l) + " is " + link.toString());
                }
            }

            path = findBestPath(lbDevice, dstDevice);
            if(path == null){
                if(flag == 1){
                    log.info("Load balancer is the only switch!");
                } else {
                    forwardRequestEndEdge(srcIp, serverIp, serverMac, linkDevice, outPort);
                    log.info("Request will be forwarded to H" + String.valueOf(targetServer));
                }
            } else {
                links = path.links();
                len_link = links.size();
                linkDevice = null;
                for (int l = 0; l < len_link; l++) {
                    Link link = links.get(l);
                    if (l == len_link - 1) {
                        linkDevice = link.dst().deviceId();
                    } else {
                        linkDevice = link.src().deviceId();
                    }
                    forwardRequestPathLBToDst(srcIp, serverIp, serverMac, link);
                    log.warn("link from LB to dest device" + String.valueOf(linkDevice) + " no." + String.valueOf(l) + " is " + link.toString());
                }
                forwardRequestEndEdge(srcIp, serverIp, serverMac, linkDevice, outPort);
                log.info("Request will be forwarded to H" + String.valueOf(targetServer));
            }

            /*packet back*/
            path = findBestPath(dstDevice, lbDevice);
            if(path == null){
                log.info("Dest device is LB!");
                //directly choose a path from LB back to src device
                path = findBestPath(lbDevice, srcDevice);
                if(path == null) {
                    log.info("Src device is LB!");
                    forwardRequestBackToStartEdge(srcIp, srcPortInit, lbDevice, serverIp);
                    log.info("Packet sent back to initial port:" + String.valueOf(srcPortInit) + "from device" + String.valueOf(lbDevice));
                } else {
                    links = path.links();
                    len_link = links.size();
                    linkDevice = null;
                    for (int l = 0; l < len_link; l++) {
                        Link link = links.get(l);
                        if (l == len_link - 1) {
                            linkDevice = link.dst().deviceId();
                        } else {
                            linkDevice = link.src().deviceId();
                        }
                        forwardRequestPathLBToSrc(serverIp, srcIp, link);
                        log.info("No path before, Packet directly sent back to device: " + String.valueOf(linkDevice));
                    }
                    forwardRequestBackToStartEdge(srcIp, srcPortInit, linkDevice, serverIp);
                    log.info("Packet sent back to initial port:" + String.valueOf(srcPortInit) + "from device" + String.valueOf(linkDevice));
                }
            } else {
                links = path.links();
                len_link = links.size();
                linkDevice = null;
                for (int l = 0; l < len_link; l++) {
                    Link link = links.get(l);
                    if (l == len_link - 1) {
                        linkDevice = link.dst().deviceId();
                    } else {
                        linkDevice = link.src().deviceId();
                    }
                    forwardRequestPathDstToLB( srcIp, serverIp,link);
                    log.info("Packet sent packet back to LB from device: " + String.valueOf(link.src().deviceId()));
                }
                //LB back to src device & port
                path = findBestPath(lbDevice, srcDevice);
                if(path == null) {
                    log.info("Src device is LB!");
                    forwardRequestBackToStartEdge(srcIp, srcPortInit, linkDevice, serverIp);
                    log.info("Packet sent back to initial port:" + String.valueOf(srcPortInit) + "from device" + String.valueOf(linkDevice));
                } else {
                    links = path.links();
                    len_link = links.size();
                    linkDevice = null;
                    for (int l = 0; l < len_link; l++) {
                        Link link = links.get(l);
                        if (l == len_link - 1) {
                            linkDevice = link.dst().deviceId();
                        } else {
                            linkDevice = link.src().deviceId();
                        }
                        forwardRequestPathLBToSrc(serverIp, srcIp, link);
                        log.info("Packet sent back to device: " + String.valueOf(linkDevice));
                    }

                    forwardRequestBackToStartEdge(srcIp, srcPortInit, linkDevice, serverIp);
                    log.info("Packet sent back to initial port:" + String.valueOf(srcPortInit) + "from device" + String.valueOf(linkDevice));
                }

            }

            context.block();
            return;
        } //processor

        public void forwardRequestPath(Link link, TrafficSelector selector) {
            PortNumber portNumber = link.src().port();
            TrafficTreatment treatmentP = DefaultTrafficTreatment.builder()
                    .setEthDst(MacAddress.valueOf("00:00:00:00:00:14"))
                    .setIpDst(valueOf("10.0.0.100"))
                    .setOutput(portNumber)
                    .build();

            ForwardingObjective forwardingObjectiveP = DefaultForwardingObjective.builder().withTreatment(treatmentP)
                    .withSelector(selector)
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(link.src().deviceId(), forwardingObjectiveP);
        }

        public void forwardRequestPathLBToDst(IpAddress srcIp, IpAddress servIp, MacAddress servMac, Link link){
            PortNumber port = link.src().port();
            TrafficSelector.Builder selectorLBToDst = DefaultTrafficSelector.builder();
            selectorLBToDst.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(srcPort))
                    .matchTcpDst(TpPort.tpPort(dstPort))
                    .matchIPSrc(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(valueOf("10.0.0.100"), IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentLBToDst = DefaultTrafficTreatment.builder()
                    .setEthDst(servMac)
                    .setIpDst(servIp)
                    .setOutput(port)
                    .build();

            ForwardingObjective forwardingObjectiveLBToDst = DefaultForwardingObjective.builder().withTreatment(treatmentLBToDst)
                    .withSelector(selectorLBToDst.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(link.src().deviceId(), forwardingObjectiveLBToDst);
        }

        public void forwardRequestPathDstToLB(IpAddress srcIp, IpAddress servIp, Link link){
            PortNumber port = link.src().port();
            TrafficSelector.Builder selectorDstToLB = DefaultTrafficSelector.builder();
            selectorDstToLB.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(dstPort))
                    .matchTcpDst(TpPort.tpPort(srcPort))
                    .matchIPSrc(IpPrefix.valueOf(servIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentDstToLB = DefaultTrafficTreatment.builder()
                    .setOutput(port)
                    .build();

            ForwardingObjective forwardingObjectiveDstToLB = DefaultForwardingObjective.builder().withTreatment(treatmentDstToLB)
                    .withSelector(selectorDstToLB.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(link.src().deviceId(), forwardingObjectiveDstToLB);
        }



        //way back from LB to initial src device
        public void forwardRequestPathLBToSrc(IpAddress servIp, IpAddress srcIp, Link link) {
            PortNumber port = link.src().port();
            TrafficSelector.Builder selectorBackToSrcPathEdge = DefaultTrafficSelector.builder();
            selectorBackToSrcPathEdge.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(dstPort))
                    .matchTcpDst(TpPort.tpPort(srcPort))
                    .matchIPSrc(IpPrefix.valueOf(servIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentBackToSrcPathEdge = DefaultTrafficTreatment.builder()
                    .setEthSrc(MacAddress.valueOf("00:00:00:00:00:14"))
                    .setIpSrc(valueOf("10.0.0.100"))
                    .setOutput(port)
                    .build();

            ForwardingObjective forwardingObjectiveBackToSrcPathEdge = DefaultForwardingObjective.builder().withTreatment(treatmentBackToSrcPathEdge)
                    .withSelector(selectorBackToSrcPathEdge.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(link.src().deviceId(), forwardingObjectiveBackToSrcPathEdge);

            TrafficSelector.Builder selectorBackToSrcPath = DefaultTrafficSelector.builder();
            selectorBackToSrcPath.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(dstPort)) //reverse TCP src&dst port??
                    .matchTcpDst(TpPort.tpPort(srcPort))
                    .matchIPSrc(IpPrefix.valueOf(valueOf("10.0.0.100"), IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentBackToSrcPath = DefaultTrafficTreatment.builder()
                    .setOutput(port)
                    .build();

            ForwardingObjective forwardingObjectiveBackToSrcPath = DefaultForwardingObjective.builder().withTreatment(treatmentBackToSrcPath)
                    .withSelector(selectorBackToSrcPath.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(link.src().deviceId(), forwardingObjectiveBackToSrcPath);

        }

        public void forwardRequestEndEdge(IpAddress srcIp, IpAddress servIp, MacAddress servMac, DeviceId endDeviceId, PortNumber port){
            TrafficSelector.Builder selectorToEndPort = DefaultTrafficSelector.builder();
            selectorToEndPort.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(srcPort))
                    .matchTcpDst(TpPort.tpPort(dstPort))
                    .matchIPSrc(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(valueOf("10.0.0.100"), IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentToEndPort = DefaultTrafficTreatment.builder()
                    .setEthDst(servMac)
                    .setIpDst(servIp)
                    .setOutput(port)
                    .build();

            ForwardingObjective forwardingObjectiveToEndPort = DefaultForwardingObjective.builder().withTreatment(treatmentToEndPort)
                    .withSelector(selectorToEndPort.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(endDeviceId, forwardingObjectiveToEndPort);

            TrafficSelector.Builder selectorPathToEndPort = DefaultTrafficSelector.builder();
            selectorPathToEndPort.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(srcPort))
                    .matchTcpDst(TpPort.tpPort(dstPort))
                    .matchIPSrc(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(servIp, IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentPathToEndPort = DefaultTrafficTreatment.builder()
                    .setOutput(port)
                    .build();

            ForwardingObjective forwardingObjectivePathToEndPort = DefaultForwardingObjective.builder().withTreatment(treatmentPathToEndPort)
                    .withSelector(selectorPathToEndPort.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(endDeviceId, forwardingObjectivePathToEndPort);
        }

        public void forwardRequestBackToStartEdge(IpAddress srcIp, PortNumber srcPortInit, DeviceId startEdgeId, IpAddress servIp){
            TrafficSelector.Builder selectorToStartPort = DefaultTrafficSelector.builder();
            selectorToStartPort.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(dstPort))
                    .matchTcpDst(TpPort.tpPort(srcPort))
                    .matchIPSrc(IpPrefix.valueOf(valueOf("10.0.0.100"), IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentToStartPort = DefaultTrafficTreatment.builder()
                    .setOutput(srcPortInit)
                    .build();

            ForwardingObjective forwardingObjectiveToStartPort = DefaultForwardingObjective.builder().withTreatment(treatmentToStartPort)
                    .withSelector(selectorToStartPort.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(startEdgeId, forwardingObjectiveToStartPort);


            TrafficSelector.Builder selectorToStartPort2 = DefaultTrafficSelector.builder();
            selectorToStartPort2.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(dstPort))
                    .matchTcpDst(TpPort.tpPort(srcPort))
                    .matchIPSrc(IpPrefix.valueOf(servIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchIPDst(IpPrefix.valueOf(srcIp, IpPrefix.MAX_INET_MASK_LENGTH));

            TrafficTreatment treatmentToStartPort2 = DefaultTrafficTreatment.builder()
                    .setEthSrc(MacAddress.valueOf("00:00:00:00:00:14"))
                    .setIpSrc(valueOf("10.0.0.100"))
                    .setOutput(srcPortInit)
                    .build();

            ForwardingObjective forwardingObjectiveToStartPort2 = DefaultForwardingObjective.builder().withTreatment(treatmentToStartPort2)
                    .withSelector(selectorToStartPort2.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(startEdgeId, forwardingObjectiveToStartPort2);
        }

    }

    private ConcurrentHashMap<MacAddress, ConcurrentHashMap<DeviceId,PortNumber>> LookupTableUpdate(int size){
        MacAddress serverMac;
        for (int i = 0; i < size; i++){
            ConcurrentHashMap<DeviceId, PortNumber> locationTable;
            serverMac = serverMacList.get(i);
            if(hostService.getHostsByMac(serverMac).isEmpty()){
                log.warn("Cannot find server mac: " + String.valueOf(serverMac));
                if(serverLookupTable.containsKey(serverMac)){
                    serverLookupTable.remove(serverMac);
                    log.warn("Remove server mac: " + String.valueOf(serverMac) + " from server list!");
                }
            } else {
                if(!serverLookupTable.containsKey(serverMac)){
                    log.info("Adding new Mac: "+ serverMac.toString());
                    locationTable = new ConcurrentHashMap<>();
                    serverLookupTable.put(serverMac, locationTable);
                } else {
                    log.info("start adding location table");
                    locationTable = serverLookupTable.get(serverMac);
                }
                Set<Host> serverS = hostService.getHostsByMac(serverMac);
                log.info("find server set" + String.valueOf(serverS));
                Iterator<Host> server_it = serverS.iterator();
                Host server = server_it.next();
                DeviceId switchId = server.location().deviceId();
                log.info("find server deviceID" + String.valueOf(switchId));
                PortNumber serverPort = server.location().port();
                if (!locationTable.containsKey(switchId)){
                    log.info("Adding new switch: "+switchId.toString()+" for server MAC "+serverMac.toString());
                    locationTable.put(switchId, serverPort);
                    serverLookupTable.replace(serverMac,locationTable);
                } else {
                    if(!(locationTable.get(switchId).equals(serverPort))){
                        log.info("Overwrite port no. : "+ String.valueOf(serverPort)+" for device ID "+ String.valueOf(switchId));
                        locationTable.put(switchId, serverPort);
                        serverLookupTable.replace(serverMac,locationTable);
                    }
                }


            }

        }
        return serverLookupTable;
    }

    private  MacAddress outPortSelectionNoLB(){
        MacAddress targetServerMac = MacAddress.valueOf(server2_mac);//used for no LB test
        return targetServerMac;
    }

    private  MacAddress outPortSelectionRR(List<MacAddress> serverList){
//        Ip4Address targetServerIp = serverList.get(2);//used for no LB test
        MacAddress targetServerMac = null;
        switch(requestsServed % 3){
            case 0:
                targetServerMac = serverList.get(0);
                requestsServed++;
                break;
            case 1:
                targetServerMac = serverList.get(1);
                requestsServed++;
                break;
            case 2:
                targetServerMac = serverList.get(2);
                requestsServed++;
                break;
        }
        return targetServerMac;
    }


    private Set<Path> findKShortestPath(DeviceId src, DeviceId dst){
        log.info("Start to find all available paths...");
        Stream<Path> pstream = topologyService.getKShortestPaths(topologyService.currentTopology(), src, dst);
        //Stream -> Set
        Set<Path> pathSet = pstream.collect(Collectors.toSet());
        log.info("K-Path-size: " + pathSet.size());
        return pathSet;

    }

    private Path findBestPath(DeviceId srcDevice, DeviceId dstDevice){
        Set<Path> pathSet = findKShortestPath(srcDevice, dstDevice);
        if(pathSet.isEmpty()) return null;
        else {
            if(pathSet.size() == 1){
                Path path = pathSet.iterator().next();
                return path;
            } else {
                ConcurrentHashMap<Long, Path> pathRcvBytes = new ConcurrentHashMap<>();
                for (Path p : pathSet) {
                    long rcvBytes_max = 0;
                    log.info("path is: " + String.valueOf(p.links()));
                    List<Link> links = p.links();
                    for (Link l : links) {
                        PortStatistics dstPortStats = deviceService.getDeltaStatisticsForPort(l.dst().deviceId(), l.dst().port());
                        long rcvBytes = dstPortStats.bytesReceived();
                        if(rcvBytes >= rcvBytes_max){
                            rcvBytes_max = rcvBytes;
                        }
                    }
                    log.info("path received maximum bytes: " + String.valueOf(rcvBytes_max));
                    pathRcvBytes.put(rcvBytes_max, p);
                }
                log.info("path received bytes list: " + String.valueOf(pathRcvBytes));
                Long rcvBytesList_min = Collections.min(pathRcvBytes.keySet());
                log.info("Minimum path received bytes: " + String.valueOf(rcvBytesList_min));
                Path selectedPath = pathRcvBytes.get(rcvBytesList_min);
                log.info("Select the path: " + String.valueOf(selectedPath));
                return selectedPath;
            }
        }
    }

}
