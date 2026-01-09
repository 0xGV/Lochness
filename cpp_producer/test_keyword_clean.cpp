#include <iostream>
#include <string>
#include <vector>

std::wstring CleanKeyword(std::wstring keyword) {
  if (keyword.empty())
    return keyword;

  // Check for wrapping braces
  if (keyword.size() >= 2 && keyword.front() == L'{' &&
      keyword.back() == L'}') {
    keyword = keyword.substr(1, keyword.size() - 2);
  }

  // Check for leading comma-space which sometimes happens with empty first bit
  // format: ", KEYWORD"
  if (keyword.size() >= 2 && keyword.substr(0, 2) == L", ") {
    keyword = keyword.substr(2);
  }

  // Replace ", " with " | "
  std::wstring result;
  std::wstring delimiter = L", ";
  std::wstring replacement = L" | ";
  size_t pos = 0;
  size_t prev = 0;

  while ((pos = keyword.find(delimiter, prev)) != std::wstring::npos) {
    result += keyword.substr(prev, pos - prev);
    result += replacement;
    prev = pos + delimiter.length();
  }
  result += keyword.substr(prev);

  return result;
}

int main() {
  std::wstring raw = L"{, KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_DOWN}";
  std::wstring expected =
      L"KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_DOWN";

  std::wstring cleaned = CleanKeyword(raw);

  std::wcout << L"Raw:      " << raw << std::endl;
  std::wcout << L"Cleaned:  " << cleaned << std::endl;
  std::wcout << L"Expected: " << expected << std::endl;

  if (cleaned == expected) {
    std::wcout << L"PASS" << std::endl;
    return 0;
  } else {
    std::wcout << L"FAIL" << std::endl;
    return 1;
  }
}
