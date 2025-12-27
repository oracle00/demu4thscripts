# -*- coding: utf-8 -*-
# text_compare.py

def read_multiline(prompt):
    print(prompt)
    print("(終了するには空行を2回入力してください)")
    lines = []
    empty_count = 0

    while True:
        line = input()
        if line == "":
            empty_count += 1
            if empty_count >= 2:
                break
        else:
            empty_count = 0
        lines.append(line)

    # 最後の空行2つは除去
    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines)


def main():
    ref_text = read_multiline("=== リファレンステキストを貼り付けてください ===")
    cmp_text = read_multiline("=== 比較対象テキストを貼り付けてください ===")

    print("\n=== 判定結果 ===")
    if ref_text == cmp_text:
        print("完全一致")
    else:
        print("一致しません")


if __name__ == "__main__":
    main()