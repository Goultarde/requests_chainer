package com.example.burpchain;

import org.junit.jupiter.api.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.zip.GZIPOutputStream;
import static org.junit.jupiter.api.Assertions.*;

class AutoChainFinderTest {
    static final java.nio.charset.Charset UTF8 = StandardCharsets.UTF_8;
    static final java.nio.charset.Charset LATIN1 = StandardCharsets.ISO_8859_1;
    static byte[] response(String body) { return ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body).getBytes(UTF8); }
    static byte[] request(String target) { return ("GET " + target + " HTTP/1.1\r\nHost: local\r\n\r\n").getBytes(UTF8); }

    @Test void followsRecursiveDependenciesAndIgnoresNoiseAndOtherOrigins() throws Exception {
        var history = List.of(
            new AutoChainFinder.Capture(1,"local","start",request("/start"),response("{\"session\":\"session-first123\"}")),
            new AutoChainFinder.Capture(2,"other","cross-origin",request("/start"),response("{\"session\":\"session-first123\"}")),
            new AutoChainFinder.Capture(3,"local","noise",request("/noise"),response("{\"noise\":\"unrelated987654\"}")),
            new AutoChainFinder.Capture(4,"local","middle",request("/middle?session=session-first123"),response("{\"ticket\":\"ticket-second123\"}")),
            new AutoChainFinder.Capture(5,"local","target",request("/finish/ticket-second123"),response("{}")));
        var plan = new AutoChainFinder(history).find(4);
        assertEquals(List.of(1,4,5), plan.steps().stream().map(s -> s.capture().id()).toList());
        assertEquals(2, plan.links().size());
        assertTrue(new String(plan.steps().getLast().template(), LATIN1).contains("|bytes}}"));
    }

    @Test void responseMustExistBeforeConsumerAndAnalysisDoesNotInspectLaterTraffic() throws Exception {
        var history = List.of(
            new AutoChainFinder.Capture(1,"local","too late",request("/slow"),response("{\"id\":\"session-first123\"}"),0,50),
            new AutoChainFinder.Capture(2,"local","target",request("/finish/session-first123"),response("{}"),20,30),
            new AutoChainFinder.Capture(3,"local","future",request("/future"),response("{\"id\":\"session-first123\"}"),40,45));
        var plan = new AutoChainFinder(history).find(1);
        assertEquals(1, plan.steps().size());
        assertTrue(plan.links().isEmpty());
    }

    @Test void prefersMostRecentProducerAndRejectsWrongOrigin() throws Exception {
        var history = List.of(
            new AutoChainFinder.Capture(1,"local","first",request("/first"),response("{\"id\":\"same-value-123\"}")),
            new AutoChainFinder.Capture(2,"local","second",request("/second"),response("{\"id\":\"same-value-123\"}")),
            new AutoChainFinder.Capture(3,"local","target",request("/same-value-123"),response("{}")));
        var plan = new AutoChainFinder(history).find(2);
        assertEquals(List.of(2,3), plan.steps().stream().map(s -> s.capture().id()).toList());
    }

    @Test void decodesChunkedGzipJsonAndExtractsEscapedPointer() throws Exception {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (var gzip = new GZIPOutputStream(compressed)) { gzip.write("{\"nested\":[{\"access/ticket\":\"value-12345678\"}]}".getBytes(UTF8)); }
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        raw.writeBytes("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n".getBytes(UTF8));
        raw.writeBytes((Integer.toHexString(compressed.size()) + "\r\n").getBytes(UTF8));
        raw.writeBytes(compressed.toByteArray()); raw.writeBytes("\r\n0\r\n\r\n".getBytes(UTF8));
        String selector = AutoValue.selector(new AutoValue.Recipe("json","/nested/0/access~1ticket","http","raw"));
        assertEquals("value-12345678", new String(AutoValue.extract(raw.toByteArray(), selector), UTF8));
        assertThrows(IOException.class, () -> AutoValue.extract(response("{}"), selector));
    }

    @Test void limitsDecompressedData() throws Exception {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (var gzip = new GZIPOutputStream(compressed)) { gzip.write(new byte[AutoValue.MAX_BYTES + 1]); }
        assertThrows(IOException.class, () -> AutoValue.decoded(new AutoValue.Message(Map.of(),compressed.toByteArray()), "gzip"));
    }

    @Test void rendersBinaryPlaceholdersWithoutChangingAdjacentBytes() {
        byte[] bytes = {0, (byte)255, (byte)128, 13, 10, (byte)233};
        byte[] template = "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\nprefix{{challenge|bytes}}suffix".getBytes(UTF8);
        byte[] rendered = ByteTemplate.render(template,Map.of("challenge",Base64.getEncoder().encodeToString(bytes)),s -> s.getBytes(UTF8));
        byte[] expectedBody = new byte[6 + bytes.length + 6];
        System.arraycopy("prefix".getBytes(UTF8),0,expectedBody,0,6);
        System.arraycopy(bytes,0,expectedBody,6,bytes.length);
        System.arraycopy("suffix".getBytes(UTF8),0,expectedBody,6 + bytes.length,6);
        assertArrayEquals(expectedBody, uncheckedBody(rendered));
        assertTrue(new String(rendered,LATIN1).contains("Content-Length: 18"));
    }
    private static byte[] uncheckedBody(byte[] message) {
        try { return AutoValue.message(message).body(); } catch(IOException ex) { throw new AssertionError(ex); }
    }

    @Test void discoversAndReplaysComplexLiveAppTwiceWithFreshBinaryAndTextValues() throws Exception {
        Process process = new ProcessBuilder("python3", "-u", "-c",
            "from server import Handler, ThreadingHTTPServer; s=ThreadingHTTPServer(('127.0.0.1',0),Handler); print(s.server_port,flush=True); s.serve_forever()")
            .directory(Path.of("../test-app").toFile()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            BufferedReader reader = process.inputReader();
            int port = Integer.parseInt(reader.readLine());
            List<AutoChainFinder.Capture> history = new ArrayList<>();
            byte[] start = capture(port,history,"GET","/flow/start",Map.of(),new byte[0]);
            var context = AutoValue.JSON.readTree(AutoValue.message(start).body()).at("/data/context");
            String sid=context.get("session").asText(),csrf=context.get("csrf").asText(),label=context.get("label").asText();
            capture(port,history,"GET","/flow/noise",Map.of(),new byte[0]);
            byte[] challengeResponse = capture(port,history,"GET","/flow/challenge?session="+sid,Map.of("X-CSRF",csrf),new byte[0]);
            var challenge = AutoValue.message(challengeResponse);
            String cookie=challenge.headers().get("set-cookie").getFirst().split(";",2)[0];
            byte[] answer = capture(port,history,"POST","/flow/answer?session="+sid,Map.of("X-CSRF",csrf,"Cookie",cookie,"Content-Type","application/octet-stream"),challenge.body());
            var answerMessage = AutoValue.message(answer);
            String ticket=AutoValue.JSON.readTree(AutoValue.decoded(answerMessage,"http")).at("/data/grants/0/access~1ticket").asText();
            String receipt=answerMessage.headers().get("x-receipt").getFirst();
            byte[] profileResponse=capture(port,history,"GET","/flow/profile?session="+sid,Map.of("X-CSRF",csrf),new byte[0]);
            String profile=AutoValue.JSON.readTree(AutoValue.message(profileResponse).body()).at("/data/profile/id").asText();
            byte[] reserveBody=AutoValue.JSON.writeValueAsBytes(Map.of("session",sid,"credentials",Map.of("ticket",ticket)));
            String encodedLabel=new String(AutoValue.transform(label.getBytes(UTF8),"url"),UTF8);
            byte[] reservationResponse=capture(port,history,"POST","/flow/reserve/"+encodedLabel,Map.of("X-CSRF",csrf,"Content-Type","application/json"),reserveBody);
            String reservation=AutoValue.JSON.readTree(AutoValue.message(reservationResponse).body()).at("/result/reservation/id").asText();
            capture(port,history,"GET","/flow/noise",Map.of(),new byte[0]);
            byte[] finalBody=AutoValue.JSON.writeValueAsBytes(Map.of("session",sid,"profile",profile,"credentials",Map.of("ticket",ticket)));
            capture(port,history,"POST","/flow/finish/"+reservation,Map.of("X-Receipt",receipt,"Content-Type","application/json"),finalBody);
            var plan = new AutoChainFinder(history).find(history.size()-1);
            assertEquals(6,plan.steps().size(),plan.links().toString());
            assertFalse(plan.steps().stream().anyMatch(s -> s.capture().label().contains("noise")));
            assertTrue(plan.links().stream().anyMatch(l -> l.description().contains("Complete body (wire)")));
            assertTrue(plan.links().stream().anyMatch(l -> l.description().contains("JSON /data/grants/0/access~1ticket (http)")));
            assertTrue(plan.links().stream().anyMatch(l -> l.description().contains("Cookie flow_cookie")));
            assertTrue(plan.links().stream().anyMatch(l -> l.description().endsWith("→ url")));
            List<ChainEngine.Step> definitions=plan.steps().stream().map(s -> new ChainEngine.Step(new String(s.template(),LATIN1),s.outputs())).toList();
            Set<String> sessions=new HashSet<>(Set.of(sid));
            for(int run=0;run<2;run++) {
                List<byte[]> responses=new ArrayList<>();
                ChainEngine.run(definitions,(index,ignored,variables) -> {
                    byte[] rendered=ByteTemplate.render(plan.steps().get(index).template(),variables,s -> s.getBytes(UTF8));
                    byte[] response=exchange(port,rendered); responses.add(response);
                    return new ChainEngine.Response(status(response),new String(response,LATIN1),response);
                },message -> {});
                String newSession=AutoValue.JSON.readTree(AutoValue.message(responses.getFirst()).body()).at("/data/context/session").asText();
                assertTrue(sessions.add(newSession));
                var finished=AutoValue.JSON.readTree(AutoValue.message(responses.getLast()).body());
                assertTrue(finished.at("/result/completed").asBoolean());
                assertEquals(newSession,finished.at("/result/session").asText());
                assertFalse(Arrays.equals(challenge.body(),AutoValue.message(responses.get(1)).body()));
            }
        } finally { process.destroy(); if(!process.waitFor(3,java.util.concurrent.TimeUnit.SECONDS)) process.destroyForcibly(); }
    }
    private static int status(byte[] response) { return Integer.parseInt(new String(response,0,32,LATIN1).split(" ")[1]); }
    private static byte[] capture(int port,List<AutoChainFinder.Capture> captures,String method,String path,Map<String,String> headers,byte[] body) throws Exception {
        ByteArrayOutputStream raw=new ByteArrayOutputStream();
        raw.writeBytes((method+" "+path+" HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nConnection: close\r\nContent-Length: "+body.length+"\r\n").getBytes(UTF8));
        for(var entry:headers.entrySet()) raw.writeBytes((entry.getKey()+": "+entry.getValue()+"\r\n").getBytes(UTF8));
        raw.writeBytes("\r\n".getBytes(UTF8)); raw.writeBytes(body);
        byte[] response=exchange(port,raw.toByteArray());
        assertEquals(200,status(response),new String(response,LATIN1));
        captures.add(new AutoChainFinder.Capture(captures.size()+1,"local",method+" "+path,raw.toByteArray(),response));
        return response;
    }
    private static byte[] exchange(int port,byte[] request) throws Exception {
        try(Socket socket=new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1",port),3000); socket.setSoTimeout(5000);
            socket.getOutputStream().write(request); socket.getOutputStream().flush();
            return socket.getInputStream().readAllBytes();
        }
    }
}
