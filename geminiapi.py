from google import generative as genai

genai.configure(api_key ="AIzaSyByu3LRbXKPdVeaELIjnJAOC3jGNFYMp38")
generation_config =  dict(
    temperature= 1,
    max_output_tokens=8192,
    top_k=40,
    top_p=0.95,
    response_mine_type="text/plain",
    
)

