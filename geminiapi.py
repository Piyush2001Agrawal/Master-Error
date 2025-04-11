from google import generative as genai

genai.configure(api_key ="AIzaSyByu3LRbXKPdVeaELIjnJAOC3jGNFYMp38")
generation_config =  dict(
    temperature= 1,
    max_output_tokens=8192,
    top_k=40,
    top_p=0.95,
    response_mine_type="text/plain",
    
)


def executor():
    model = genai.GenerativeModel(
        model_name = "gemini-2.0-flash-exp",
        generation_config=generation_config,
        system_instruction=(
            """
Assume you are a universal code executor:
- Detect the code language and display it.
- Execute the code and provide the output.
- If error occurs, then give output of the error.
- If error comes include potential errors and improvements.
"""
        )
    )

    return model


def analyzer():
    model = genai.GenerativeModel(
        model_name = "gemini-2.0-flash-exp",
        generation_config=generation_config,
        system_instruction=(
            """
Assume you are a code generator:
- keep output simple and organized.
- if user inputs any code, detect the code language and give suggestions for possible errors.
- Provide correction code using optimized functions or classes.
- Always include potential errors and improvements.
- Summarize the output and incluide examples with both functions and classes and some.
- if user input any code \ndetect the code language and give suggestions of possible errors and give correction code using optimized functions or classes\n- give us possible errors\n- and give the improvemnet in functions OR classses always for every code \n- organized and summarized the output in simple way and also include one example with function and one with class\n- more simple it and short it\n- need not to print Next Steps:\n\nI am ready to provide more details on more complex code.\n If programming language doesnot support function or class then show the best way to implement it with other languages. and give a simplest summary why use this language.\nI am ready to give potential error and improvements for complex code.\n
"""
        )

    )

    return model

