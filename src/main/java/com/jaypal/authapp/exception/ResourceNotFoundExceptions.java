package com.jaypal.authapp.exception;

public class ResourceNotFoundExceptions extends RuntimeException{
    public ResourceNotFoundExceptions(String message){
        super(message);
    }

    public ResourceNotFoundExceptions(){
        super("Resource Not Found!!");
    }
}
