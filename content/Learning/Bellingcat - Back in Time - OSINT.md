---
created: 2025-05-11
lastmod: 2025-05-11
tags:
- bellingcat
- osint
- google dorks
- wayback machine
- exiftool
image: /static/note-thumbnails/bellingcat.jpg
---

<img src="/static/note-thumbnails/bellingcat.jpg" alt="bellingcat logo" style="max-width: 700px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">

https://bellingcat-challenges.beehiiv.com/p/back-in-time-with-sofia-santos

Time to complete: ~3 hours
### Challenge 1 - Fresh Faced

>[!help]- Challenge - Finding the founder
>
>![[Images/Pasted image 20250511123530.png]]
>
>*The story of Bellingcat starts with its founder, Eliot Higgins.*
>
>*In 2013, numerous media outlets reached out to him to learn more about his groundbreaking discoveries. Some featured him in print, others published articles online, and a few produced and aired video reports.*
>
>*The image above shows a screenshot from a newspaper article. That interview was also recorded.*
>
>*Your task is to find footage of this interview on YouTube, and provide the code at the end of the link (answer format: dQw4w9WgXcQ).*

>[!success]- Answer - Find the video
>Using Google, I searched for results that contained the string `eliot higgins`, where from the website `youtube.com` and were dated in `2013`.
>
>On the 9th page I found a result for a video with a thumbnail that was similar to the sample image. The video title was also in a language that appeared similar to the language in the sample image (Slovenian):
>
>![[Images/Pasted image 20250511135251.png]]
>
>[Link to the search result.](https://www.google.com/search?q=%22eliot+higgins%22+site:youtube.com&sca_esv=73452592aa508339&tbs=cdr:1,cd_min:1/1/2013,cd_max:12/31/2013&ei=A50gaJCLKtqwhbIPpe-NgAI&start=80&sa=N&sstk=Af40H4VVMFIh4BOq-A1nZky6cuCCTwukGr64Wx85Msf6866NpF5Vx39ErwqNqBEhRed6NJA8DAJw-QKvgHX5WekUdhz1RK72eP-9VSfIreJxPrhblx-12cr5Z19UNImedNQ9ftheoWaeZXEbH2t3uZkPPXI5jlTAXAi90VSajn_o7XH_45MqHeXltJbpqkN5AkEuCLySCJHePTk_VPcw5o4lppEoIXiGsSgQzJOR-w4-HK0LAE-v9D4AkP4b-S40LinoemJr3-Y4Qgtg5jvmoEcSUN6XC_BFlBYfIvVeNDrnLQp_EvBICj9Kq1of&ved=2ahUKEwjQmOaeupuNAxVaWEEAHaV3AyA4RhDy0wN6BAgHEBM&biw=1083&bih=958&dpr=1) 
>
>About `1:50` is the exact point the screenshot is from:
>
>![[Images/Pasted image 20250511135746.png]]
>
>The URL for the video is `https://www.youtube.com/watch?v=k7qd4Y6QAfY`:
>
>![[Images/Pasted image 20250511140009.png]]
>
>So, the answer to the challenge is: `k7qd4Y6QAfY`:
>
>![[Images/Pasted image 20250511140105.png]]
### Challenge 2 - Training Time

>[!question]- Challenge - There's a lot to learn
>
>![[Images/Pasted image 20250511140241.png]]

>[!code]- Find the event
>A search for `bellingcat christiaan triebert` reveals [Christiaan's Twitter account](https://x.com/trbrtc): 
>
>![[Images/Pasted image 20250511145234.png]]
>
>The account appears quite active. There's a good chance that Christiaan would have tweeted *something* to do with the workshop he was leading at the time.
>
>I use [Twitter's advanced search](https://x.com/search?q=%22workshop%22%20(from%3Atrbrtc)%20until%3A2017-12-31%20since%3A2017-12-01&src=typed_query) to see all tweets by `@trbrtc` (Christiaan) that contain the phrase `workshop` and are dated between `1st December 2017` and `31st December 2017` (the workshop was said to take place in December 2017).
>
>![[Images/Pasted image 20250511145828.png]]
>![[Images/Pasted image 20250511145842.png]]
>![[Images/Pasted image 20250511145858.png]]
>
>There are only three results, the first of which says *"participants of the Bellingcat workshop at **ARIJ17**"*:
>
>![[Images/Pasted image 20250511145655.png]]
>
>I see what else has been [tweeted about ARIJ17](https://x.com/hashtag/ARIJ17?src=hashtag_click), and consequently find [a tweet](https://x.com/noor_surib/status/985825492312961024) containing a photo that appears to show the same room:
>
>![[Images/Pasted image 20250511150050.png]]
>
>It appears this is the event that the source photo was taken at. Now I need to find where the event was held...

>[!code]- Find the building
>[Another tweet](https://x.com/noor_surib/status/936611558632902661) using the `ARIJ17` tag has a photo of a woman (possibly an attendee) standing in front of, what appears to be, an event poster:
>
>![[Images/Pasted image 20250511150644.png]]
>
>The tweet's text (roughly) [translates to](https://www.deepl.com/en/translator#ar/en/%D8%A7%D9%86%D8%B7%D9%84%D8%A7%D9%82%20%20%D9%85%D9%84%D8%AA%D9%82%D9%89%20%D8%A7%D8%B1%D9%8A%D8%AC%20%D8%A7%D9%84%D8%B3%D9%86%D9%88%D9%8A%20%D8%A7%D9%84%D8%B9%D8%A7%D8%B4%D8%B1%20%D9%84%D9%84%D8%B5%D8%AD%D8%A7%D9%81%D8%A9%20%D8%A7%D9%84%D8%A7%D8%B3%D8%AA%D9%82%D8%B5%D8%A7%D8%A6%D9%8A%D8%A9%20%D8%A7%D9%84%D8%B9%D8%B1%D8%A8%D9%8A%D8%A9%20.) *The tenth annual ARIJ Forum for Arab Investigative Journalism kicks off*:
>
>![[Images/Pasted image 20250511150726.png]]
>
>A [Google search](https://www.google.com/search?q=arij+forum+2017&oq=arij+forum+2017&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIHCAEQIRigAdIBCDIyMDFqMGo3qAIAsAIA&sourceid=chrome&ie=UTF-8) for `arij forum 2017` leads to an [ARIJ Forum Q & A webpage](https://arij17.arij.net/arij-forum-q-a/index9ed2.html?lang=en) which appears to reveal the event's location as the `Mövenpick Resort and Spa Dead Sea`:
>
>![[Images/Pasted image 20250511151447.png]]

>[!success]- Answer - Find the name of the room
>A [Google search](https://www.google.com/search?q=M%C3%B6venpick+Resort+and+Spa+Dead+Sea+conference+rooms&oq=M%C3%B6venpick+Resort+and+Spa+Dead+Sea+conference+rooms&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIHCAEQIRigATIHCAIQIRiPAjIHCAMQIRiPAtIBCDQ3MjhqMGo0qAIAsAIB&sourceid=chrome&ie=UTF-8) for `Mövenpick Resort and Spa Dead Sea conference rooms` gives the first result for [a webpage](https://movenpick.accor.com/en/middle-east/jordan/dead-sea/resort-dead-sea/meeting-rooms.html) on the hotel's website which gives several of the available conference rooms, one of which looks similar, if not the same, to the room in the source photo - it's called `The Grand Ball Room`:
>
>![[Images/Pasted image 20250511151819.png]]
>
>A bigger photo of `The Grand Ball Room` on this [webpage](https://movenpick.accor.com/en/middle-east/jordan/dead-sea/resort-dead-sea/meeting-rooms/the-grand-ball-room.html):
>
>![[Images/Pasted image 20250511151910.png]]
>
>Correct!
>
>![[Images/Pasted image 20250511152000.png]]
### Challenge 3 - Creating Community

>[!question]- Challenge - A new place to connect
>
>![[Images/Pasted image 20250511152211.png]]

>[!code]- Find the tweet and the Discord server
>Using [Twitter's advanced search](https://x.com/search?lang=en-GB&q=%22discord%20server%22%20(from%3Abellingcat)%20until%3A2020-05-31%20since%3A2020-05-01&src=typed_query) I searched for any tweets by `@bellingcat` which contained the phrase `discord server` and was dated between `1st May 2020` and `31st May 2020` (the discord server was said to have been created in May 2020):
>
>The [source tweet](https://x.com/bellingcat/status/1260211332437213184) is the first result:
>
>![[Images/Pasted image 20250511152824.png]]
>
>The Twitter UI gives the tweet's timestamp as 15:12 on 12th May 2020, which is assumed to be my local time, British Summer Time:
>
>![[Images/Pasted image 20250511152906.png]]
>
>After clicking the link within the tweet, I added myself to the server:
>
>![[Images/Pasted image 20250511153303.png]]

>[!code]- Find when the Discord server was created
>To get an idea how this could be done, I asked ChatGPT (arguably this is a more direct way of getting an answer compared to a Google search).
>
>ChatGPT suggests if I know the Server ID then I can use a decoder to get the creation timestamp for that server:
>
>![[Images/Pasted image 20250511153543.png]]
>
>After enabling Developer mode within my Discord account's settings, I copy the Server ID for the Bellingcat Discord server:
>
>![[Images/Pasted image 20250511153655.png]]
>
>I [search](https://www.google.com/search?q=discord+snowflake&oq=discord+snowflake&gs_lcrp=EgZjaHJvbWUqBwgAEAAYgAQyBwgAEAAYgAQyBwgBEAAYgAQyBwgCEAAYgAQyBwgDEAAYgAQyBwgEEAAYgAQyBwgFEAAYgAQyDQgGEAAYhgMYgAQYigUyDQgHEAAYhgMYgAQYigUyDQgIEAAYhgMYgAQYigUyBwgJEAAY7wXSAQg0MTgyajBqNKgCALACAQ&sourceid=chrome&ie=UTF-8) for `discord snowflake`, which finds a [Discord Snowflake to Timestamp Converter](https://snowsta.mp/):
>
>![[Images/Pasted image 20250511153833.png]]
>
>I paste in the Server ID, which [returns a timestamp](https://snowsta.mp/?l=en-us&z=k&f=gu21mqrxi2-vj) of `12th May 2020 14:04 (BST)`:
>
>![[Images/Pasted image 20250511153915.png]]
>

>[!success]- Answer - Finding the difference in time
>So, the Discord server was created at `14:04 (BST) on 12th May 2020` and the tweet was made at `15:12 (BST) on 12th May 2020`. This gives a time difference of `68 minutes`.
>
>![[Images/Pasted image 20250511154544.png]]
### Challenge 4 - Future Plans

>[!question]- Challenge - A timely document
>
>![[Images/Pasted image 20250511154641.png]]

>[!code]- Find when Bellingcat registered their organisation in The Netherlands
>A [Google search](https://www.google.com/search?q=bellingcat+foundation+netherlands&oq=bellingcat+foundation+netherlands&gs_lcrp=EgZjaHJvbWUyCwgAEEUYChg5GKAB0gEINDMzOWowajeoAgCwAgA&sourceid=chrome&ie=UTF-8) for `bellingcat foundation netherlands` returns the Bellingcat's [About page](https://www.bellingcat.com/about/general-information/), which suggests the organisation was registered in the Netherlands on `11 July 2018` (the KvK number suggests this the Netherlands registration - KvK being [the number assigned when a business registers in the Dutch Business Register](https://www.kvk.nl/en/starting/kvk-number-all-you-need-to-know/)):
>
>![[Images/Pasted image 20250511160302.png]]
>
>

>[!code]- Find the document and the author
>The document is said to have been released nearly two years after the organisation was registered in The Netherlands. This gives a period between `11 July 2018` and `11 July 2020`.
>
>A [Google search](https://www.google.com/search?q=site%3Abellingcat.com+%22future%22+%28filetype%3Apdf+OR+filetype%3Adoc+OR+filetype%3Adocx+OR+filetype%3Axls+OR+filetype%3Axlsx+OR+filetype%3Appt+OR+filetype%3Apptx+OR+filetype%3Atxt+OR+filetype%3Artf+OR+filetype%3Acsv%29&sca_esv=97acbeea5a2701d8&biw=1083&bih=992&tbs=cdr%3A1%2Ccd_min%3A7%2F11%2F2019%2Ccd_max%3A7%2F11%2F2020&ei=rL4gaMbaOY61i-gPgoHDqQI&ved=0ahUKEwjG4Omr2puNAxWO2gIHHYLAMCUQ4dUDCBA&uact=5&oq=site%3Abellingcat.com+%22future%22+%28filetype%3Apdf+OR+filetype%3Adoc+OR+filetype%3Adocx+OR+filetype%3Axls+OR+filetype%3Axlsx+OR+filetype%3Appt+OR+filetype%3Apptx+OR+filetype%3Atxt+OR+filetype%3Artf+OR+filetype%3Acsv%29&gs_lp=Egxnd3Mtd2l6LXNlcnAivgFzaXRlOmJlbGxpbmdjYXQuY29tICJmdXR1cmUiIChmaWxldHlwZTpwZGYgT1IgZmlsZXR5cGU6ZG9jIE9SIGZpbGV0eXBlOmRvY3ggT1IgZmlsZXR5cGU6eGxzIE9SIGZpbGV0eXBlOnhsc3ggT1IgZmlsZXR5cGU6cHB0IE9SIGZpbGV0eXBlOnBwdHggT1IgZmlsZXR5cGU6dHh0IE9SIGZpbGV0eXBlOnJ0ZiBPUiBmaWxldHlwZTpjc3YpSABQAFgAcAB4AJABAJgBAKABAKoBALgBA8gBAPgBAZgCAKACAJgDAJIHAKAHALIHALgHAA&sclient=gws-wiz-serp) for a document of several types (see screenshot), from the site `bellingcat.com`, containing the word `future` and dated between `11 July 2019` and `11 July 2020` returns one result - a [Policy Plan 2019 - 2021 PDF](https://www.bellingcat.com/app/uploads/2020/06/Bellingcat-Policy-Plan-2019-2021.pdf).
>
>This policy plan appears to have been posted on `22 June 2020` - almost two years since the organisation was registered within The Netherlands:
>
>![[Images/Pasted image 20250511162032.png]]
>
>Using exiftool, the document's metadata has a metadata `author` tag set to `Aric Toler`:
>
>![[Images/Pasted image 20250511162136.png]]

>[!success]- Answer - Find the article and its last word
>To find a list of articles authored by Aric Toler, I first [search Google](https://www.google.com/search?q=bellingcat+articles&sca_esv=6b5001a3b62373fd&ei=QMEgaObzJrzPhbIPw-eH6Qg&ved=0ahUKEwjmk7Lm3JuNAxW8Z0EAHcPzIY0Q4dUDCBA&uact=5&oq=bellingcat+articles&gs_lp=Egxnd3Mtd2l6LXNlcnAiE2JlbGxpbmdjYXQgYXJ0aWNsZXMyBhAAGBYYHjIFEAAY7wUyCBAAGIAEGKIEMgUQABjvBTIFEAAY7wVIpAxQWljtC3ABeACQAQCYAW2gAdsFqgEDNy4yuAEDyAEA-AEBmAIIoALTBcICBRAAGIAEwgIFEC4YgATCAgsQABiABBiRAhiKBcICDhAAGIAEGJECGMcDGIoFwgIJEAAYFhjHAxgewgILEAAYgAQYhgMYigWYAwCIBgGSBwM2LjKgB-kmsgcDNi4yuAfTBQ&sclient=gws-wiz-serp) for `bellingcat artiles`, which leads me to Bellingcat's [articles page](https://www.bellingcat.com/category/resources/articles/). From here, I click the [first article](https://www.bellingcat.com/resources/2025/03/03/the-bellingcat-open-source-challenge-is-back/), then click on the first listed author's name:
>
>![[Images/Pasted image 20250511162734.png]]
>
>This results in a webpage with the URL `[...]/author/merl`.
>
>![[Images/Pasted image 20250511162851.png]]
>
>I change it to `[...]/author/aric`, in the hope that it would list Aric's articles instead, but no luck:
>
>![[Images/Pasted image 20250511162959.png]]
>
>I see what the other author's URL is, and notice this time the format is `[...]/author/<first name><last name>`:
>
>![[Images/Pasted image 20250511163055.png]]
>
>So I try `[...]/author/arictoler` instead, and [this time](https://www.bellingcat.com/author/arictoler/) it lists articles by that author:
>
>![[Images/Pasted image 20250511163130.png]]
>
>Now it's just a case of going through these articles to find the one published closest to `22 June 2020`. I'm assuming the articles are sorted from newest at the beginning to oldest at the end. I find [this article](https://www.bellingcat.com/resources/case-studies/2020/10/14/testing-twitters-methods-of-restricting-blocked-links-and-domains/) posted on `October 14, 2020` and [the one before it](https://www.bellingcat.com/resources/how-tos/2020/04/15/how-not-to-report-on-russian-disinformation/) posted on `April 15, 2020`. The latter was posted nearest to 22 June 2020:
>
>![[Images/Pasted image 20250511163519.png]]
>
>The article's last word is `record`:
>
>![[Images/Pasted image 20250511163540.png]]
>
>Success:
>
>![[Images/Pasted image 20250511163608.png]]
### Challenge 5 - Toolkit Tracing

>[!question]- Challenge - Tool tips new and old
>
>![[Images/Pasted image 20250511163657.png]]

>[!code]- Find a version of the Toolkit from 2020
>A Google search for `osint landscape` (another name for the tool going round, as shown within the source screenshot) from 2020 reveals a `start.me` URL that comes up repeatedly:
>
>![[Images/Pasted image 20250511204153.png]]
>
>That link has expired:
>
>![[Images/Pasted image 20250511204214.png]]
>
>However, the contents of the link were preserved within the WayBack Machine:
>
>![[Images/Pasted image 20250511204308.png]]
>
>In it, there's a link to a Google Docs document. The link, [when visited not through the WayBack Machine](https://docs.google.com/document/d/1BfLPJpRtyq4RFtHJoNpvWQjmGnyVkfE2HYoICKOGguA), is also not available:
>
>![[Images/Pasted image 20250511204533.png]]
>
>But it is available through the [WayBack Machine](https://web.archive.org/web/20200728143048/https://docs.google.com/document/d/1BfLPJpRtyq4RFtHJoNpvWQjmGnyVkfE2HYoICKOGguA/edit):
>
>![[Images/Pasted image 20250511204615.png]]
>

>[!success]- Answer - Find the missing document and the word within it
>The WayBack Machine version of the Google Docs Bellingcat OSINT Toolkit from 2020 contains a link to a `FEAT VERSION 1.1` PDF:
>
>![[Images/Pasted image 20250511204806.png]]
>
>That link can't be clicked, but a [Google search](https://www.google.com/search?q=%22FEAT_Version_1.1%22&sca_esv=01f6517ce83cc516&ei=NvwgaJjJC4ikhbIPhurk6A8&ved=0ahUKEwiYvMeDlZyNAxUIUkEAHQY1Gf0Q4dUDCBA&uact=5&oq=%22FEAT_Version_1.1%22&gs_lp=Egxnd3Mtd2l6LXNlcnAiEiJGRUFUX1ZlcnNpb25fMS4xIkiptAFQAFjnrwFwCngAkAECmAG7A6AB7BmqAQoxOC42LjMuMC4xuAEDyAEA-AEC-AEBmAIZoAKYC8ICBhAAGAcYHsICCxAAGIAEGJECGIoFwgIKEAAYgAQYQxiKBcICCxAAGIAEGLEDGIMBwgIOEC4YgAQYsQMY0QMYxwHCAgQQABgewgIIEC4YBxgKGB7CAggQABgHGAoYHsICChAAGAUYBxgKGB7CAgYQABgKGB7CAggQABgHGAgYHsICCBAAGIAEGKIEwgIFEAAY7wXCAgYQABgIGB7CAgsQABiABBiGAxiKBZgDAJIHBDIyLjOgB_yEAbIHBDEzLjO4B98K&sclient=gws-wiz-serp) for `FEAT_VERSION_1.1` returns the document we're after within [the first result](https://digitallibrary.un.org/record/670986/files/FEAT_Version_1-1.pdf):
>
>![[Images/Pasted image 20250511204907.png]]
>
>Within that document we find a table on page 39, the first hazard within that table being `Explosive`:
>
>![[Images/Pasted image 20250511205008.png]]
>
>Success
>
>![[Images/Pasted image 20250511203801.png]]

<img src="/static/completed-thumbnails/bellingcat-back-in-time.png" alt="htb writeup" style="max-width: 700px; height: auto; display: block; margin: 0 auto; box-shadow: 0px 0px 14px 0px rgba(0,0,0,0.9);">