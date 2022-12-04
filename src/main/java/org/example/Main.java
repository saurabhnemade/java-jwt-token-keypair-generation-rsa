package org.example;

public class Main {
    public static void main(String args[]) throws Exception {
        CorrectJwtCreator jwtCreator = new CorrectJwtCreator();
        String data = "{\"name\":\"Saurabh Nemade\"}";
        jwtCreator.generateToken(data);
    }
}
