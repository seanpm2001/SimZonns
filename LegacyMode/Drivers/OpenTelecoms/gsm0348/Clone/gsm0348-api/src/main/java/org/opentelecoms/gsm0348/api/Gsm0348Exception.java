package org.opentelecoms.gsm0348.api;

/**
 * General library exception
 * 
 * @author Victor Platov
 * */
public class Gsm0348Exception extends Exception
{
	private static final long serialVersionUID = -593113341925505030L;

	public Gsm0348Exception()
	{
	}

	public Gsm0348Exception(String message)
	{
		super(message);
	}

	public Gsm0348Exception(Throwable cause)
	{
		super(cause);
	}

	public Gsm0348Exception(String message, Throwable cause)
	{
		super(message, cause);
	}

}
