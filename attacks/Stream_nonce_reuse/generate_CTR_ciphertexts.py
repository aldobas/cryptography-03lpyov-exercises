from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode

key = get_random_bytes(16)
nonce = b'0'

cipher = AES.new(key,AES.MODE_CTR,nonce=nonce)

english_sentences = [
b'This book is sure to liquefy your brain.',
b'The swirled lollipop had issues with the pop rock candy.',
b'There are few things better in life than a slice of pie.',
b'The view from the lighthouse excited even the most seasoned traveler.',
b'She was sad to hear that fireflies are facing extinction due to artificial light, habitat loss, and pesticides.',
b'The tour bus was packed with teenage girls heading toward their next adventure.',
b'My dentist tells me that chewing bricks is very bad for your teeth.',
b'The sun had set and so had his dreams.',
b'She lived on Monkey Jungle Road and that seemed to explain all of her strangeness.',
b'There\'s a reason that roses have thorns.',
b'Of course, she loves her pink bunny slippers.',
b'The blinking lights of the antenna tower came into focus just as I heard a loud snap.',
b'Twin 4-month-olds slept in the shade of the palm tree while the mother tanned in the sun.',
b'The clouds formed beautiful animals in the sky that eventually created a tornado to wreak havoc.',
b'Fluffy pink unicorns are a popular status symbol among macho men.',
b'As he waited for the shower to warm, he noticed that he could hear water change temperature.',
b'The Tsunami wave crashed against the raised houses and broke the pilings as if they were toothpicks.',
b'With a single flip of the coin, his life changed forever.',
b'Now I need to ponder my existence and ask myself if I\'m truly real.',
b'He was disappointed when he found the beach to be so sandy and the sun so sunny.',
b'The fish dreamed of escaping the fishbowl and into the toilet where he saw his friend go.',
b'We have young kids who often walk into our room at night for various reasons including clowns in the closet.',
b'The toy brought back fond memories of being lost in the rain forest.',
b'The best key lime pie is still up for debate.',
b'The stranger officiates the meal.',
b'I would be delighted if the sea were full of cucumber juice.',
b'His mind was blown that there was nothing in space except space itself.',
b'Your girlfriend bought your favorite cookie crisp cereal but forgot to get milk.',
b'Buried deep in the snow, he hoped his batteries were fresh in his avalanche beacon.',
b'The old apple revels in its authority.',
b'Her scream silenced the rowdy teenagers.',
b'Dan ate the clouds like cotton candy.',
b'Don\'t piss in my garden and tell me you\'re trying to help my plants grow.',
b'When I cook spaghetti, I like to boil it a few minutes past al dente so the noodles are super slippery.',
b'Combines are no longer just for farms.',
b'The crowd yells and screams for more memes.',
b'The urgent care center was flooded with patients after the news of a new deadly virus was made public.',
b'Pair your designer cowboy hat with scuba gear for a memorable occasion.',
b'Nobody has encountered an explosive daisy and lived to tell the tale.',
b'The truth is that you pay for your lifestyle in hours.',
b'He wondered if she would appreciate his toenail collection.',
b'It took him a month to finish the meal.',
b'He figured a few sticks of dynamite were easier than a fishing pole to catch fish.',
b'It\'s much more difficult to play tennis with a bowling ball than it is to bowl with a tennis ball.',
b'The shooter says goodbye to his love.',
b'He didn\'t understand why the bird wanted to ride the bicycle.',
b'He dreamed of eating green apples with worms.',
b'It was her first experience training a rainbow unicorn.',
b'Courage and stupidity were all he had.',
b'The opportunity of a lifetime passed before him as he tried to decide between a cone or a cup.'
]

print(english_sentences)

output = []

for sentence in english_sentences:
    cipher = AES.new(key,AES.MODE_CTR,nonce=nonce)
    output.append(b64encode(cipher.encrypt(sentence)))



print(output)
