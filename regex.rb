#This file contains regex's for HTTP pages used by the http_get_recog function in recognizer


def html_regex(page)
	if page.include? (/ID_EESX_Welcome/)
		return "ESXI"
	elsif page.include? (//)
	end
end