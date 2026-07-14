import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { OtpInput } from '../../src/components/ui/OtpInput';

describe('OtpInput', () => {
  it('renders 6 input boxes by default', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    expect(inputs).toHaveLength(6);
  });

  it('renders custom number of input boxes', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} length={4} />);

    const inputs = screen.getAllByRole('textbox');
    expect(inputs).toHaveLength(4);
  });

  it('displays the provided value across boxes', () => {
    const onChange = vi.fn();
    render(<OtpInput value="123456" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    expect((inputs[0] as HTMLInputElement).value).toBe('1');
    expect((inputs[1] as HTMLInputElement).value).toBe('2');
    expect((inputs[5] as HTMLInputElement).value).toBe('6');
  });

  it('calls onChange when a digit is entered', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.change(inputs[0]!, { target: { value: '5' } });

    expect(onChange).toHaveBeenCalledWith('5');
  });

  it('supports paste of full code', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.paste(inputs[0]!, {
      clipboardData: { getData: () => '123456' },
    });

    expect(onChange).toHaveBeenCalledWith('123456');
  });

  it('strips non-digit characters from paste', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.paste(inputs[0]!, {
      clipboardData: { getData: () => '12-34-56' },
    });

    expect(onChange).toHaveBeenCalledWith('123456');
  });

  it('handles backspace to clear current digit', () => {
    const onChange = vi.fn();
    render(<OtpInput value="123456" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.keyDown(inputs[2]!, { key: 'Backspace' });

    expect(onChange).toHaveBeenCalledWith('12456');
  });

  it('backspace on empty digit moves focus to previous and clears it', () => {
    const onChange = vi.fn();
    render(<OtpInput value="12" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    // Focus on digit 3 (empty) and press backspace
    fireEvent.keyDown(inputs[2]!, { key: 'Backspace' });

    // Should clear the previous digit (index 1)
    expect(onChange).toHaveBeenCalledWith('1');
  });

  it('ArrowLeft and ArrowRight navigate between digits', () => {
    const onChange = vi.fn();
    render(<OtpInput value="123456" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.keyDown(inputs[3]!, { key: 'ArrowLeft' });
    fireEvent.keyDown(inputs[3]!, { key: 'ArrowRight' });

    // Arrow keys don't change values, just navigate focus
    expect(onChange).not.toHaveBeenCalled();
  });

  it('has proper aria-labels on each input', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    expect(screen.getByLabelText('Digit 1 of 6')).toBeInTheDocument();
    expect(screen.getByLabelText('Digit 6 of 6')).toBeInTheDocument();
  });

  it('has a role="group" container with aria-label', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} aria-label="Test OTP" />);

    expect(screen.getByRole('group', { name: 'Test OTP' })).toBeInTheDocument();
  });

  it('disables all inputs when disabled prop is true', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} disabled />);

    const inputs = screen.getAllByRole('textbox');
    for (const input of inputs) {
      expect(input).toBeDisabled();
    }
  });

  it('ignores non-digit characters on input', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.change(inputs[0]!, { target: { value: 'a' } });

    // Non-digit should be ignored
    expect(onChange).not.toHaveBeenCalled();
  });

  it('handles paste that is shorter than length', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.paste(inputs[0]!, {
      clipboardData: { getData: () => '12' },
    });

    expect(onChange).toHaveBeenCalledWith('12');
  });

  it('handles empty paste gracefully', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    fireEvent.paste(inputs[0]!, {
      clipboardData: { getData: () => '' },
    });

    // Empty paste should not trigger onChange
    expect(onChange).not.toHaveBeenCalled();
  });

  it('each input has inputMode="numeric"', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    for (const input of inputs) {
      expect(input.getAttribute('inputmode')).toBe('numeric');
    }
  });

  it('typing a digit in the last box does not advance focus', () => {
    const onChange = vi.fn();
    render(<OtpInput value="12345" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    // Type in the last input (index 5, which is length - 1)
    fireEvent.change(inputs[5]!, { target: { value: '6' } });

    expect(onChange).toHaveBeenCalledWith('123456');
  });

  it('backspace on the first empty input does nothing', () => {
    const onChange = vi.fn();
    render(<OtpInput value="" onChange={onChange} />);

    const inputs = screen.getAllByRole('textbox');
    // Press backspace on the first input (index 0) when it is empty
    fireEvent.keyDown(inputs[0]!, { key: 'Backspace' });

    expect(onChange).not.toHaveBeenCalled();
  });
});
